//! The face factor: takes the scan results of the user from the daemon.
//!
//! The factor takes results until the session stops it. A match ends the
//! factor at once. Every other result leaves the factor running, so that
//! the user can scan again. The last result that is not a match is the
//! provisional outcome.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use pam_biometrics_policy::{FaceClass, FaceSettings, Factor, Outcome};
use pam_biometrics_protocol::{Op, Reply, Request, ScanResult, call};

use crate::session::{Event, FaceControl, FactorTask, Stop, pause};

/// The pause between two `take` requests without a result.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// One `take` request waits at most this long for a running scan.
const TAKE_WAIT: Duration = Duration::from_secs(1);

/// The socket timeout in addition to the wait time.
const SOCKET_MARGIN: Duration = Duration::from_secs(2);

/// The socket timeout of `scan` and `status`.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// The first pause after a failed `take`. It doubles up to
/// [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_secs(1);

/// The longest pause after failed `take` requests.
const MAX_BACKOFF: Duration = Duration::from_secs(10);

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

impl Daemon {
    fn request(&self, op: Op) -> Option<Reply> {
        call(&self.socket, &Request::new(op, &self.user), CONTROL_TIMEOUT)
            .ok()
            .filter(|reply| reply.error.is_none())
    }
}

impl Source for Daemon {
    fn take(&mut self, wait: Duration) -> io::Result<Reply> {
        let mut request = Request::new(Op::Take, &self.user);
        request.wait_ms = Some(u64::try_from(wait.as_millis()).unwrap_or(u64::MAX));
        call(&self.socket, &request, wait + SOCKET_MARGIN)
    }
}

impl FaceControl for Daemon {
    fn scan(&mut self) -> bool {
        self.request(Op::Scan).is_some()
    }

    fn scanning(&mut self) -> bool {
        self.request(Op::Status)
            .is_some_and(|reply| reply.result == Some(ScanResult::Scanning))
    }
}

/// The face factor for one user.
#[derive(Debug)]
pub struct FaceTask<S = Daemon> {
    /// The source of the scan results.
    pub source: S,
    /// The resolved face thresholds.
    pub face: FaceSettings,
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
            FaceClass::Uncertain => (Outcome::NoDecision, Some("Face not certain. Scan again.")),
            FaceClass::Absent => (Outcome::NoDecision, Some("No face found.")),
        }),
    }
}

/// What [`FaceTask::take_once`] asks the loop to do next.
enum Next {
    /// Take again at once.
    Again,
    /// Take again after a pause.
    Pause(Duration),
    /// The face matched.
    Matched,
}

impl<S: Source> FaceTask<S> {
    /// Takes one result and sends its events.
    fn take_once(&mut self, backoff: &mut Duration, events: &Sender<Event>) -> Next {
        let reply = match self.source.take(TAKE_WAIT) {
            Ok(reply) if reply.error.is_none() => {
                *backoff = MIN_BACKOFF;
                reply
            }
            // The daemon is unreachable or refuses the request.
            _ => {
                let pause = *backoff;
                *backoff = (*backoff * 2).min(MAX_BACKOFF);
                return Next::Pause(pause);
            }
        };
        let Some(result) = reply.result else {
            return Next::Pause(POLL_INTERVAL);
        };
        match evaluate(&self.face, &result) {
            // The take waited for the running scan. Take again.
            None => Next::Again,
            Some((Outcome::Match, _)) => {
                let _ = events.send(Event::Finished(Factor::Face, Outcome::Match));
                Next::Matched
            }
            Some((outcome, message)) => {
                if let Some(message) = message {
                    let _ = events.send(Event::Message(message.to_owned()));
                }
                let _ = events.send(Event::Provisional(Factor::Face, outcome));
                Next::Again
            }
        }
    }

    /// Takes results until a match or a stop. Returns `true` on a match.
    /// Sends a match as the end of the factor, the other results as
    /// provisional outcomes, and [`Event::Polled`] after the first result.
    /// Requests that fail repeat after a pause, so that a restarted daemon
    /// serves the factor again.
    fn poll(&mut self, stopped: &AtomicBool, events: &Sender<Event>) -> bool {
        let is_stopped = || stopped.load(Ordering::SeqCst);
        let mut backoff = MIN_BACKOFF;
        let mut first = true;
        while !is_stopped() {
            let next = self.take_once(&mut backoff, events);
            if first {
                first = false;
                let _ = events.send(Event::Polled(Factor::Face));
            }
            match next {
                Next::Again => {}
                Next::Pause(duration) => {
                    pause(duration, is_stopped);
                }
                Next::Matched => return true,
            }
        }
        false
    }
}

impl<S: Source> FactorTask for FaceTask<S> {
    fn start(mut self: Box<Self>, events: Sender<Event>) -> Box<dyn Stop> {
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stopped);
        thread::spawn(move || self.poll(&flag, &events));
        Box::new(FaceStop(stopped))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::{self, Receiver};
    use std::time::Instant;

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

    /// Polls `source` until a match or a stop after `stop_ms`. Returns the
    /// match flag, the events, and the time.
    fn poll_source<S: Source>(source: S, stop_ms: u64) -> (bool, Vec<Event>, Duration) {
        let mut task = FaceTask {
            source,
            face: Settings::default().face,
        };
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stopped);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(stop_ms));
            flag.store(true, Ordering::SeqCst);
        });
        let (sender, receiver): (Sender<Event>, Receiver<Event>) = mpsc::channel();
        let start = Instant::now();
        let matched = task.poll(&stopped, &sender);
        let elapsed = start.elapsed();
        drop(sender);
        (matched, receiver.iter().collect(), elapsed)
    }

    /// Polls a scripted source. Returns the match flag, the events, and the
    /// number of take requests.
    fn poll(results: Vec<ScanResult>, stop_ms: u64) -> (bool, Vec<Event>, usize) {
        let takes = Arc::new(AtomicUsize::new(0));
        let source = Script {
            results: results.into(),
            takes: Arc::clone(&takes),
        };
        let (matched, events, _) = poll_source(source, stop_ms);
        (matched, events, takes.load(Ordering::SeqCst))
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
            Some((Outcome::NoDecision, Some("Face not certain. Scan again.")))
        );
        assert_eq!(
            evaluate(&face, &finished(None, 0)),
            Some((Outcome::NoDecision, Some("No face found.")))
        );
    }

    const POLLED: Event = Event::Polled(Factor::Face);
    const MATCHED: Event = Event::Finished(Factor::Face, Outcome::Match);

    #[test]
    fn absent_then_match_is_a_match() {
        let (matched, events, _) = poll(vec![ABSENT, MATCH], 3000);
        assert!(matched);
        assert_eq!(
            events,
            [
                Event::Message("No face found.".to_owned()),
                Event::Provisional(Factor::Face, Outcome::NoDecision),
                POLLED,
                MATCHED,
            ]
        );
    }

    #[test]
    fn a_first_match_comes_before_the_poll_event() {
        let (matched, events, _) = poll(vec![MATCH], 3000);
        assert!(matched);
        assert_eq!(events, [MATCHED, POLLED]);
    }

    #[test]
    fn reject_then_match_is_a_match() {
        let (matched, events, _) = poll(vec![REJECT, MATCH], 3000);
        assert!(matched);
        assert!(events.contains(&Event::Provisional(Factor::Face, Outcome::Reject)));
        assert_eq!(events.last(), Some(&MATCHED));
    }

    #[test]
    fn scanning_results_are_taken_again() {
        let (matched, events, takes) = poll(vec![ScanResult::Scanning, MATCH], 3000);
        assert!(matched);
        assert_eq!(events, [POLLED, MATCHED]);
        assert_eq!(takes, 2);
    }

    #[test]
    fn a_match_is_taken_once() {
        // A second stored match stays with the daemon.
        let (matched, _, takes) = poll(vec![MATCH, MATCH], 3000);
        assert!(matched);
        assert_eq!(takes, 1);
    }

    #[test]
    fn a_reject_keeps_the_factor_running() {
        let (matched, events, takes) = poll(vec![REJECT], 500);
        assert!(!matched);
        assert_eq!(
            events,
            [
                Event::Message("Face not recognized.".to_owned()),
                Event::Provisional(Factor::Face, Outcome::Reject),
                POLLED,
            ]
        );
        // The factor kept taking until the stop.
        assert!(takes > 1, "{takes}");
    }

    #[test]
    fn no_result_sends_only_the_poll_event() {
        let (matched, events, _) = poll(vec![], 300);
        assert!(!matched);
        assert_eq!(events, [POLLED]);
    }

    #[test]
    fn unreachable_daemon_is_retried_until_the_stop() {
        let daemon = Daemon {
            socket: PathBuf::from("/nonexistent/pam-biometrics.socket"),
            user: "alice".to_owned(),
        };
        let (matched, events, elapsed) = poll_source(daemon, 300);
        assert!(!matched);
        assert_eq!(events, [POLLED]);
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn unreachable_daemon_cannot_scan() {
        let mut daemon = Daemon {
            socket: PathBuf::from("/nonexistent/pam-biometrics.socket"),
            user: "alice".to_owned(),
        };
        assert!(!daemon.scan());
        assert!(!daemon.scanning());
    }
}
