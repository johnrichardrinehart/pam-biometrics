//! The face factor: takes the scan results of the user from the daemon.
//!
//! The factor takes results until the deadline. A match ends the factor
//! at once. Every other result leaves the factor running, so that the user
//! can scan again. The last result that is not a match is the provisional
//! outcome and counts at the deadline.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

use pam_biometrics_policy::{FaceClass, FaceSettings, Factor, Outcome};
use pam_biometrics_protocol::{Op, Reply, Request, ScanResult, call};

use crate::step::{Event, FactorTask, Stop};

/// The pause between two `take` requests without a result.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// One `take` request waits at most this long for a running scan.
const TAKE_WAIT: Duration = Duration::from_secs(1);

/// The socket timeout in addition to the wait time.
const SOCKET_MARGIN: Duration = Duration::from_secs(2);

/// A source of scan results for one user.
pub trait Source: Send + 'static {
    /// Takes and consumes the stored result. Waits at most `wait` for a
    /// running scan.
    fn take(&mut self, wait: Duration) -> io::Result<Reply>;
}

/// The daemon behind its socket.
#[derive(Debug)]
pub struct Daemon {
    /// The daemon socket.
    pub socket: PathBuf,
    /// The user.
    pub user: String,
}

impl Source for Daemon {
    fn take(&mut self, wait: Duration) -> io::Result<Reply> {
        let mut request = Request::new(Op::Take, &self.user);
        request.wait_ms = Some(u64::try_from(wait.as_millis()).unwrap_or(u64::MAX));
        call(&self.socket, &request, wait + SOCKET_MARGIN)
    }
}

/// The face factor for one user.
#[derive(Debug)]
pub struct FaceTask<S = Daemon> {
    /// The source of the scan results.
    pub source: S,
    /// The resolved face thresholds.
    pub face: FaceSettings,
    /// The end of the step.
    pub deadline: Instant,
}

struct FaceStop(Arc<AtomicBool>);

impl Stop for FaceStop {
    fn stop(self: Box<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Returns the factor outcome and a message for a scan result. Returns
/// `None` while the scan runs.
#[must_use]
pub fn evaluate(
    face: &FaceSettings,
    result: &ScanResult,
) -> Option<(Outcome, Option<&'static str>)> {
    match result {
        ScanResult::Scanning => None,
        ScanResult::NoModel => Some((Outcome::NoDecision, Some("No face enrolled."))),
        ScanResult::Finished { best, faces } => Some(match face.classify(*best, *faces) {
            FaceClass::Match => (Outcome::Match, None),
            FaceClass::Reject => (Outcome::Reject, Some("Face not recognized.")),
            FaceClass::Uncertain => (Outcome::NoDecision, Some("Face not certain.")),
            FaceClass::Absent => (Outcome::NoDecision, Some("No face found.")),
        }),
    }
}

impl<S: Source> FaceTask<S> {
    /// Takes results until a match, the deadline, or a stop. Returns the
    /// match or the last provisional outcome.
    fn poll(&mut self, stopped: &AtomicBool, events: &Sender<Event>) -> Outcome {
        let mut latest = Outcome::NoDecision;
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if stopped.load(Ordering::SeqCst) || remaining.is_zero() {
                return latest;
            }
            let reply = match self.source.take(remaining.min(TAKE_WAIT)) {
                Ok(reply) if reply.error.is_none() => reply,
                // The daemon is unreachable or refuses the request.
                _ => return latest,
            };
            let Some(result) = reply.result else {
                thread::sleep(POLL_INTERVAL.min(remaining));
                continue;
            };
            match evaluate(&self.face, &result) {
                // The take waited for the running scan. Take again.
                None => {}
                Some((Outcome::Match, _)) => return Outcome::Match,
                Some((outcome, message)) => {
                    if let Some(message) = message {
                        let _ = events.send(Event::Message(message.to_owned()));
                    }
                    let _ = events.send(Event::Provisional(Factor::Face, outcome));
                    latest = outcome;
                }
            }
        }
    }
}

impl<S: Source> FactorTask for FaceTask<S> {
    fn start(mut self: Box<Self>, events: Sender<Event>) -> Box<dyn Stop> {
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stopped);
        thread::spawn(move || {
            let outcome = self.poll(&flag, &events);
            let _ = events.send(Event::Finished(Factor::Face, outcome));
        });
        Box::new(FaceStop(stopped))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::{self, Receiver};

    use pam_biometrics_policy::Settings;

    use super::*;

    /// Returns scripted results, then no result. Counts the requests.
    struct Script {
        results: VecDeque<ScanResult>,
        takes: Arc<AtomicUsize>,
    }

    impl Source for Script {
        fn take(&mut self, _wait: Duration) -> io::Result<Reply> {
            self.takes.fetch_add(1, Ordering::SeqCst);
            Ok(Reply {
                result: self.results.pop_front(),
                ..Reply::default()
            })
        }
    }

    fn finished(best: Option<f64>, faces: u32) -> ScanResult {
        ScanResult::Finished { best, faces }
    }

    const ABSENT: ScanResult = ScanResult::Finished {
        best: None,
        faces: 0,
    };
    const MATCH: ScanResult = ScanResult::Finished {
        best: Some(0.3),
        faces: 2,
    };
    const REJECT: ScanResult = ScanResult::Finished {
        best: Some(0.8),
        faces: 5,
    };

    /// Polls a scripted source. Returns the outcome, the events, and the
    /// number of take requests.
    fn poll(results: Vec<ScanResult>, timeout_ms: u64) -> (Outcome, Vec<Event>, usize) {
        let takes = Arc::new(AtomicUsize::new(0));
        let mut task = FaceTask {
            source: Script {
                results: results.into(),
                takes: Arc::clone(&takes),
            },
            face: Settings::default().face,
            deadline: Instant::now() + Duration::from_millis(timeout_ms),
        };
        let (sender, receiver): (Sender<Event>, Receiver<Event>) = mpsc::channel();
        let outcome = task.poll(&AtomicBool::new(false), &sender);
        drop(sender);
        (
            outcome,
            receiver.iter().collect(),
            takes.load(Ordering::SeqCst),
        )
    }

    #[test]
    fn evaluate_results() {
        let face = Settings::default().face;
        assert_eq!(evaluate(&face, &ScanResult::Scanning), None);
        assert_eq!(
            evaluate(&face, &ScanResult::NoModel),
            Some((Outcome::NoDecision, Some("No face enrolled.")))
        );
        assert_eq!(
            evaluate(&face, &finished(Some(0.3), 1)),
            Some((Outcome::Match, None))
        );
        assert_eq!(
            evaluate(&face, &finished(Some(0.8), 3)),
            Some((Outcome::Reject, Some("Face not recognized.")))
        );
        assert_eq!(
            evaluate(&face, &finished(Some(0.5), 3)),
            Some((Outcome::NoDecision, Some("Face not certain.")))
        );
        assert_eq!(
            evaluate(&face, &finished(None, 0)),
            Some((Outcome::NoDecision, Some("No face found.")))
        );
    }

    #[test]
    fn absent_then_match_is_a_match() {
        let (outcome, events, _) = poll(vec![ABSENT, MATCH], 3000);
        assert_eq!(outcome, Outcome::Match);
        assert_eq!(
            events,
            [
                Event::Message("No face found.".to_owned()),
                Event::Provisional(Factor::Face, Outcome::NoDecision),
            ]
        );
    }

    #[test]
    fn reject_then_match_is_a_match() {
        let (outcome, events, _) = poll(vec![REJECT, MATCH], 3000);
        assert_eq!(outcome, Outcome::Match);
        assert!(events.contains(&Event::Provisional(Factor::Face, Outcome::Reject)));
    }

    #[test]
    fn scanning_results_are_taken_again() {
        let (outcome, events, takes) = poll(vec![ScanResult::Scanning, MATCH], 3000);
        assert_eq!(outcome, Outcome::Match);
        assert!(events.is_empty());
        assert_eq!(takes, 2);
    }

    #[test]
    fn a_match_is_taken_once() {
        // A second stored match stays with the daemon.
        let (outcome, _, takes) = poll(vec![MATCH, MATCH], 3000);
        assert_eq!(outcome, Outcome::Match);
        assert_eq!(takes, 1);
    }

    #[test]
    fn only_a_reject_gives_a_reject_at_the_deadline() {
        let (outcome, events, takes) = poll(vec![REJECT], 500);
        assert_eq!(outcome, Outcome::Reject);
        assert_eq!(
            events,
            [
                Event::Message("Face not recognized.".to_owned()),
                Event::Provisional(Factor::Face, Outcome::Reject),
            ]
        );
        // The factor kept taking until the deadline.
        assert!(takes > 1, "{takes}");
    }

    #[test]
    fn the_last_result_counts_at_the_deadline() {
        let (outcome, _, _) = poll(vec![REJECT, ABSENT], 500);
        assert_eq!(outcome, Outcome::NoDecision);
    }

    #[test]
    fn no_result_gives_no_decision_at_the_deadline() {
        let (outcome, events, _) = poll(vec![], 300);
        assert_eq!(outcome, Outcome::NoDecision);
        assert!(events.is_empty());
    }

    #[test]
    fn unreachable_daemon_gives_no_decision() {
        let mut task = FaceTask {
            source: Daemon {
                socket: PathBuf::from("/nonexistent/pam-biometrics.socket"),
                user: "alice".to_owned(),
            },
            face: Settings::default().face,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let (sender, _receiver) = mpsc::channel();
        let start = Instant::now();
        assert_eq!(
            task.poll(&AtomicBool::new(false), &sender),
            Outcome::NoDecision
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
