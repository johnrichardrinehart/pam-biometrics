//! Runs the enabled factors in parallel and decides the PAM step.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use pam_biometrics_policy::{Combine, Factor, Outcome, Settings, Verdict};

/// A message from a running factor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A line for the user.
    Message(String),
    /// The factor still runs. This outcome applies if the deadline passes
    /// before the factor ends. A later event replaces it.
    Provisional(Factor, Outcome),
    /// The factor ended.
    Finished(Factor, Outcome),
}

/// Stops a running factor and releases its device.
pub trait Stop {
    /// Stops the factor. The factor sends no more events after this call.
    fn stop(self: Box<Self>);
}

/// A factor that runs in the background.
pub trait FactorTask: Send {
    /// Starts the factor. The factor reports through `events`.
    fn start(self: Box<Self>, events: Sender<Event>) -> Box<dyn Stop>;
}

/// The result of [`run`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepResult {
    /// The decision.
    pub verdict: Verdict,
    /// The outcome of each factor that ended before the decision. After the
    /// deadline, it also holds the provisional outcomes.
    pub finished: BTreeMap<Factor, Outcome>,
}

/// Starts `tasks`, writes their messages to `out`, and waits until the
/// policy decides or `timeout` passes. Stops every task before it returns.
///
/// A provisional outcome counts only after the deadline, with one
/// exception: with `combine: all`, a provisional reject decides at once,
/// because no later outcome can make the step succeed.
pub fn run(
    settings: &Settings,
    tasks: Vec<Box<dyn FactorTask>>,
    timeout: Duration,
    out: &mut dyn Write,
) -> StepResult {
    let deadline = Instant::now() + timeout;
    let (sender, events) = mpsc::channel();
    let stops: Vec<Box<dyn Stop>> = tasks
        .into_iter()
        .map(|task| task.start(sender.clone()))
        .collect();
    drop(sender);

    let mut finished = BTreeMap::new();
    let mut provisional = BTreeMap::new();
    let mut disconnected = false;
    let (verdict, outcomes) = loop {
        let now = Instant::now();
        let deadline_passed = disconnected || now >= deadline;
        let mut outcomes = finished.clone();
        if deadline_passed {
            for (factor, outcome) in &provisional {
                outcomes.entry(*factor).or_insert(*outcome);
            }
        }
        if let Some(verdict) = settings.decide(&outcomes, deadline_passed) {
            break (verdict, outcomes);
        }
        match events.recv_timeout(deadline.saturating_duration_since(now)) {
            Ok(Event::Message(text)) => {
                let _ = writeln!(out, "{text}");
                let _ = out.flush();
            }
            Ok(Event::Provisional(factor, outcome)) => {
                if settings.combine == Combine::All && outcome == Outcome::Reject {
                    finished.entry(factor).or_insert(outcome);
                }
                provisional.insert(factor, outcome);
            }
            Ok(Event::Finished(factor, outcome)) => {
                finished.entry(factor).or_insert(outcome);
            }
            Err(RecvTimeoutError::Timeout) => {}
            // Every factor ended. The ones without an outcome give no decision.
            Err(RecvTimeoutError::Disconnected) => disconnected = true,
        }
    };
    for stop in stops {
        stop.stop();
    }
    StepResult {
        verdict,
        finished: outcomes,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;

    use pam_biometrics_policy::{Combine, OnNoDecision, StepOutcome};

    use super::*;

    /// A factor that sends scripted events after delays.
    struct Mock {
        script: Vec<(u64, Event)>,
        /// Keep the channel open after the script, as a waiting device does.
        hold: bool,
        log: Arc<Mutex<Vec<String>>>,
        name: &'static str,
    }

    struct MockStop {
        log: Arc<Mutex<Vec<String>>>,
        name: &'static str,
    }

    impl Stop for MockStop {
        fn stop(self: Box<Self>) {
            self.log.lock().unwrap().push(format!("stop {}", self.name));
        }
    }

    impl FactorTask for Mock {
        fn start(self: Box<Self>, events: Sender<Event>) -> Box<dyn Stop> {
            let stop = MockStop {
                log: Arc::clone(&self.log),
                name: self.name,
            };
            thread::spawn(move || {
                for (delay, event) in self.script {
                    thread::sleep(Duration::from_millis(delay));
                    if events.send(event).is_err() {
                        return;
                    }
                }
                if self.hold {
                    thread::sleep(Duration::from_secs(5));
                }
            });
            Box::new(stop)
        }
    }

    struct Harness {
        log: Arc<Mutex<Vec<String>>>,
        tasks: Vec<Box<dyn FactorTask>>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                log: Arc::new(Mutex::new(Vec::new())),
                tasks: Vec::new(),
            }
        }

        fn factor(mut self, name: &'static str, script: Vec<(u64, Event)>, hold: bool) -> Self {
            self.tasks.push(Box::new(Mock {
                script,
                hold,
                log: Arc::clone(&self.log),
                name,
            }));
            self
        }

        fn run(
            self,
            combine: Combine,
            on_no_decision: OnNoDecision,
            timeout_ms: u64,
        ) -> (StepResult, String, Vec<String>, Duration) {
            let settings = Settings {
                combine,
                on_no_decision,
                ..Settings::default()
            };
            let mut out = Vec::new();
            let start = Instant::now();
            let result = run(
                &settings,
                self.tasks,
                Duration::from_millis(timeout_ms),
                &mut out,
            );
            let elapsed = start.elapsed();
            let log = self.log.lock().unwrap().clone();
            (result, String::from_utf8(out).unwrap(), log, elapsed)
        }
    }

    fn finished(factor: Factor, outcome: Outcome) -> Event {
        Event::Finished(factor, outcome)
    }

    #[test]
    fn face_match_wins_while_the_finger_waits() {
        let (result, out, log, elapsed) = Harness::new()
            .factor("fingerprint", vec![], true)
            .factor(
                "face",
                vec![(50, finished(Factor::Face, Outcome::Match))],
                false,
            )
            .run(Combine::Any, OnNoDecision::Allow, 3000);
        assert_eq!(result.verdict.outcome, StepOutcome::Success);
        assert_eq!(result.finished.get(&Factor::Face), Some(&Outcome::Match));
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert_eq!(out, "");
        assert_eq!(log, ["stop fingerprint", "stop face"]);
    }

    #[test]
    fn wrong_finger_rejects_after_the_retries() {
        let (result, out, log, _) = Harness::new()
            .factor(
                "fingerprint",
                vec![
                    (
                        10,
                        Event::Message("Fingerprint not recognized. Try again.".to_owned()),
                    ),
                    (
                        10,
                        Event::Message("Fingerprint not recognized. Try again.".to_owned()),
                    ),
                    (10, finished(Factor::Fingerprint, Outcome::Reject)),
                ],
                false,
            )
            .factor(
                "face",
                vec![(10, finished(Factor::Face, Outcome::NoDecision))],
                false,
            )
            .run(Combine::Any, OnNoDecision::Allow, 3000);
        assert_eq!(result.verdict.combined, Outcome::Reject);
        assert_eq!(result.verdict.outcome, StepOutcome::Reject);
        assert_eq!(
            out,
            "Fingerprint not recognized. Try again.\nFingerprint not recognized. Try again.\n"
        );
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn any_reject_waits_for_the_face_until_the_deadline() {
        let (result, _, _, elapsed) = Harness::new()
            .factor(
                "fingerprint",
                vec![(10, finished(Factor::Fingerprint, Outcome::Reject))],
                false,
            )
            .factor("face", vec![], true)
            .run(Combine::Any, OnNoDecision::Allow, 300);
        assert_eq!(result.verdict.outcome, StepOutcome::Reject);
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    }

    #[test]
    fn any_reject_then_face_match_succeeds() {
        let (result, _, _, _) = Harness::new()
            .factor(
                "fingerprint",
                vec![(10, finished(Factor::Fingerprint, Outcome::Reject))],
                false,
            )
            .factor(
                "face",
                vec![(100, finished(Factor::Face, Outcome::Match))],
                false,
            )
            .run(Combine::Any, OnNoDecision::Allow, 3000);
        assert_eq!(result.verdict.outcome, StepOutcome::Success);
    }

    #[test]
    fn all_rejects_at_once() {
        let (result, _, _, elapsed) = Harness::new()
            .factor(
                "fingerprint",
                vec![(10, finished(Factor::Fingerprint, Outcome::Reject))],
                false,
            )
            .factor("face", vec![], true)
            .run(Combine::All, OnNoDecision::Allow, 3000);
        assert_eq!(result.verdict.outcome, StepOutcome::Reject);
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn all_needs_both_matches() {
        let (result, _, _, _) = Harness::new()
            .factor(
                "fingerprint",
                vec![(10, finished(Factor::Fingerprint, Outcome::Match))],
                false,
            )
            .factor(
                "face",
                vec![(50, finished(Factor::Face, Outcome::Match))],
                false,
            )
            .run(Combine::All, OnNoDecision::Allow, 3000);
        assert_eq!(result.verdict.outcome, StepOutcome::Success);
        assert_eq!(result.finished.len(), 2);

        let (result, _, _, _) = Harness::new()
            .factor(
                "fingerprint",
                vec![(10, finished(Factor::Fingerprint, Outcome::Match))],
                false,
            )
            .factor("face", vec![], true)
            .run(Combine::All, OnNoDecision::Allow, 200);
        assert_eq!(result.verdict.outcome, StepOutcome::NoDecision);
    }

    #[test]
    fn timeout_gives_no_decision_or_deny() {
        let (result, _, log, elapsed) = Harness::new()
            .factor("fingerprint", vec![], true)
            .factor("face", vec![], true)
            .run(Combine::Any, OnNoDecision::Allow, 200);
        assert_eq!(result.verdict.outcome, StepOutcome::NoDecision);
        assert!(elapsed >= Duration::from_millis(200));
        assert_eq!(log.len(), 2);

        let (result, _, _, _) = Harness::new()
            .factor("fingerprint", vec![], true)
            .factor("face", vec![], true)
            .run(Combine::Any, OnNoDecision::Deny, 200);
        assert_eq!(result.verdict.combined, Outcome::NoDecision);
        assert_eq!(result.verdict.outcome, StepOutcome::Reject);
    }

    #[test]
    fn unavailable_factors_end_the_step_early() {
        let (result, _, _, elapsed) = Harness::new()
            .factor(
                "fingerprint",
                vec![(10, finished(Factor::Fingerprint, Outcome::NoDecision))],
                false,
            )
            .factor(
                "face",
                vec![(10, finished(Factor::Face, Outcome::NoDecision))],
                false,
            )
            .run(Combine::Any, OnNoDecision::Allow, 3000);
        assert_eq!(result.verdict.outcome, StepOutcome::NoDecision);
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn factors_that_end_without_an_outcome_give_no_decision() {
        let (result, _, _, elapsed) = Harness::new()
            .factor("fingerprint", vec![], false)
            .factor("face", vec![], false)
            .run(Combine::Any, OnNoDecision::Allow, 3000);
        assert_eq!(result.verdict.outcome, StepOutcome::NoDecision);
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    fn provisional(factor: Factor, outcome: Outcome) -> Event {
        Event::Provisional(factor, outcome)
    }

    #[test]
    fn provisional_reject_counts_at_the_deadline() {
        let (result, _, _, elapsed) = Harness::new()
            .factor(
                "fingerprint",
                vec![(10, finished(Factor::Fingerprint, Outcome::NoDecision))],
                false,
            )
            .factor(
                "face",
                vec![(10, provisional(Factor::Face, Outcome::Reject))],
                true,
            )
            .run(Combine::Any, OnNoDecision::Allow, 300);
        assert_eq!(result.verdict.outcome, StepOutcome::Reject);
        assert_eq!(result.finished.get(&Factor::Face), Some(&Outcome::Reject));
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    }

    #[test]
    fn provisional_reject_then_match_succeeds() {
        let (result, _, _, _) = Harness::new()
            .factor("fingerprint", vec![], true)
            .factor(
                "face",
                vec![
                    (10, provisional(Factor::Face, Outcome::Reject)),
                    (50, finished(Factor::Face, Outcome::Match)),
                ],
                true,
            )
            .run(Combine::Any, OnNoDecision::Allow, 3000);
        assert_eq!(result.verdict.outcome, StepOutcome::Success);
    }

    #[test]
    fn later_provisional_outcome_replaces_the_earlier_one() {
        let (result, _, _, _) = Harness::new()
            .factor(
                "face",
                vec![
                    (10, provisional(Factor::Face, Outcome::Reject)),
                    (10, provisional(Factor::Face, Outcome::NoDecision)),
                ],
                true,
            )
            .run(Combine::Any, OnNoDecision::Allow, 300);
        assert_eq!(result.verdict.combined, Outcome::NoDecision);
    }

    #[test]
    fn all_provisional_reject_decides_at_once() {
        let (result, _, _, elapsed) = Harness::new()
            .factor("fingerprint", vec![], true)
            .factor(
                "face",
                vec![(10, provisional(Factor::Face, Outcome::Reject))],
                true,
            )
            .run(Combine::All, OnNoDecision::Allow, 3000);
        assert_eq!(result.verdict.outcome, StepOutcome::Reject);
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }
}
