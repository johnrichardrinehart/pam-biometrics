//! The helper session between `pam_biometrics.so start` and `finish`.
//!
//! The factors run in the background for the whole session. The PAM module
//! and the session talk in lines over the standard input and output of the
//! helper. See [`crate::helper`] for the protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use pam_biometrics_policy::{
    Combine, EXIT_NO_DECISION, Factor, OnNoDecision, Outcome, Settings, StepOutcome, Verdict,
};

/// `finish` waits at most this long for the first poll of the face factor.
const FIRST_POLL_LIMIT: Duration = Duration::from_secs(5);

/// A message from a running factor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A line for the user.
    Message(String),
    /// The factor still runs. This outcome applies at the end of the
    /// session unless a later event replaces it.
    Provisional(Factor, Outcome),
    /// The factor ended.
    Finished(Factor, Outcome),
    /// The factor asked its source once. The results that the source held
    /// before the session have arrived.
    Polled(Factor),
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

/// Starts face scans and reports a running scan.
pub trait FaceControl {
    /// Starts a face scan for the user. Returns false if the daemon refuses
    /// the request or is unreachable.
    fn scan(&mut self) -> bool;
    /// Returns true while a face scan for the user runs.
    fn scanning(&mut self) -> bool;
}

/// The response of the user to an `ask` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The response was the face trigger.
    Trigger,
    /// Any other response.
    Other,
}

/// A command from the PAM module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// `scan`: start a face scan.
    Scan,
    /// `state`: report the current state.
    State,
    /// `finish`: decide the step, then exit.
    Finish,
    /// `answer trigger` or `answer other`: the response to `ask`.
    Answer(Answer),
    /// `stop`: stop the factors and exit.
    Stop,
}

impl Command {
    /// Parses a command line. Returns `None` for an unknown command.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        Some(match line.trim_end_matches(['\r', '\n']) {
            "scan" => Self::Scan,
            "state" => Self::State,
            "finish" => Self::Finish,
            "answer trigger" => Self::Answer(Answer::Trigger),
            "answer other" => Self::Answer(Answer::Other),
            "stop" => Self::Stop,
            _ => return None,
        })
    }
}

/// An input of the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// An event of a factor.
    Event(Event),
    /// A command of the PAM module.
    Command(Command),
    /// The PAM module closed the connection.
    Closed,
}

/// Sleeps for `duration` unless `stopped` turns true first. Returns false
/// if `stopped` turned true.
pub fn pause(duration: Duration, stopped: impl Fn() -> bool) -> bool {
    const SLICE: Duration = Duration::from_millis(50);
    let end = Instant::now() + duration;
    loop {
        if stopped() {
            return false;
        }
        let now = Instant::now();
        if now >= end {
            return true;
        }
        thread::sleep(SLICE.min(end - now));
    }
}

/// Returns the line for a recognized factor.
#[must_use]
pub const fn recognized(factor: Factor) -> &'static str {
    match factor {
        Factor::Fingerprint => "Fingerprint recognized.",
        Factor::Face => "Face recognized.",
    }
}

/// Returns the line that `finish` shows after the decision. A match shows
/// nothing here: the session shows each recognized factor when it
/// matches.
#[must_use]
pub fn conclusion(settings: &Settings, verdict: Verdict) -> Option<&'static str> {
    match verdict.combined {
        Outcome::Reject => Some("Not recognized."),
        Outcome::NoDecision if verdict.outcome == StepOutcome::Reject => Some(
            match (
                settings.enabled(Factor::Fingerprint),
                settings.enabled(Factor::Face),
                settings.combine,
            ) {
                (true, true, Combine::Any) => "A fingerprint or a face is necessary.",
                (true, true, Combine::All) => "A fingerprint and a face are necessary.",
                (true, false, _) => "A fingerprint is necessary.",
                _ => "A face is necessary.",
            },
        ),
        Outcome::Match | Outcome::NoDecision => None,
    }
}

/// What [`Session::next`] received.
enum Next {
    /// An event or a command that the session handled itself.
    Handled,
    /// `finish`.
    Finish,
    /// `answer`.
    Answer(Answer),
    /// `stop`, or the PAM module closed the connection.
    End,
    /// The deadline passed.
    Timeout,
}

/// The state of one session.
#[derive(Debug)]
pub struct Session<'a, F, W> {
    settings: &'a Settings,
    finish_prompt: String,
    inputs: Receiver<Input>,
    face: F,
    out: W,
    /// The outcome of each factor that ended.
    finished: BTreeMap<Factor, Outcome>,
    /// The last outcome of each factor that still runs.
    provisional: BTreeMap<Factor, Outcome>,
    /// The user asked for a face scan in `finish`. The next face result
    /// ends the face factor.
    face_final: bool,
    /// The factors that asked their source at least once.
    polled: BTreeSet<Factor>,
}

impl<'a, F: FaceControl, W: Write> Session<'a, F, W> {
    /// Creates a session. `finish_prompt` is the text of the `ask` line.
    pub fn new(
        settings: &'a Settings,
        finish_prompt: String,
        inputs: Receiver<Input>,
        face: F,
        out: W,
    ) -> Self {
        Self {
            settings,
            finish_prompt,
            inputs,
            face,
            out,
            finished: BTreeMap::new(),
            provisional: BTreeMap::new(),
            face_final: false,
            polled: BTreeSet::new(),
        }
    }

    /// Handles inputs until `finish` decides or the PAM module stops the
    /// session. Returns the helper exit code.
    pub fn run(mut self) -> i32 {
        loop {
            match self.next(None) {
                Next::Handled | Next::Answer(_) | Next::Timeout => {}
                Next::Finish => return self.finish(),
                Next::End => return EXIT_NO_DECISION,
            }
        }
    }

    fn send(&mut self, line: &str) {
        // A closed connection ends the session through `Input::Closed`.
        let _ = writeln!(self.out, "{line}");
        let _ = self.out.flush();
    }

    fn info(&mut self, text: &str) {
        self.send(&format!("info {text}"));
    }

    /// Receives one input and handles events, `scan`, and `state`.
    fn next(&mut self, deadline: Option<Instant>) -> Next {
        let input = match deadline {
            None => self.inputs.recv().unwrap_or(Input::Closed),
            Some(deadline) => {
                match self
                    .inputs
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                {
                    Ok(input) => input,
                    Err(RecvTimeoutError::Timeout) => return Next::Timeout,
                    Err(RecvTimeoutError::Disconnected) => Input::Closed,
                }
            }
        };
        match input {
            Input::Event(event) => self.on_event(event),
            Input::Command(Command::Scan) => {
                self.scan();
            }
            Input::Command(Command::State) => self.report_state(),
            Input::Command(Command::Finish) => return Next::Finish,
            Input::Command(Command::Answer(answer)) => return Next::Answer(answer),
            Input::Command(Command::Stop) | Input::Closed => return Next::End,
        }
        Next::Handled
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Message(text) => self.info(&text),
            Event::Polled(factor) => {
                self.polled.insert(factor);
            }
            Event::Provisional(factor, outcome) => {
                if factor == Factor::Face && self.face_final {
                    self.face_final = false;
                    self.finished.insert(factor, outcome);
                }
                // With `combine: all`, a reject decides: no later outcome
                // can make the step succeed.
                if self.settings.combine == Combine::All && outcome == Outcome::Reject {
                    self.finished.entry(factor).or_insert(outcome);
                }
                self.provisional.insert(factor, outcome);
            }
            Event::Finished(factor, outcome) => {
                if outcome == Outcome::Match {
                    self.info(recognized(factor));
                }
                if factor == Factor::Face {
                    self.face_final = false;
                }
                self.finished.insert(factor, outcome);
            }
        }
    }

    /// Starts a face scan. Returns false if no scan runs.
    fn scan(&mut self) -> bool {
        if !self.settings.enabled(Factor::Face) {
            return false;
        }
        let started = self.face.scan();
        if !started {
            self.info("The face scan did not start.");
        }
        started
    }

    fn report_state(&mut self) {
        let verdict = match self.settled().map(|verdict| verdict.outcome) {
            Some(StepOutcome::Success) => "success",
            Some(StepOutcome::Reject) => "reject",
            _ => "pending",
        };
        let face = if self.settings.enabled(Factor::Face) && self.face.scanning() {
            "scanning"
        } else {
            "idle"
        };
        self.send(&format!("state {verdict} {face}"));
    }

    /// The outcomes so far: the ended factors and the last outcome of the
    /// running factors.
    fn happened(&self) -> BTreeMap<Factor, Outcome> {
        let mut outcomes = self.provisional.clone();
        outcomes.extend(&self.finished);
        outcomes
    }

    /// The verdict from the outcomes so far, if they give a match or a
    /// reject.
    fn settled(&self) -> Option<Verdict> {
        self.settings
            .decide(&self.happened(), true)
            .filter(|verdict| verdict.combined != Outcome::NoDecision)
    }

    /// The verdict from the outcomes so far, with no decision for the
    /// factors without an outcome.
    fn current(&self) -> Verdict {
        self.settings
            .decide(&self.happened(), true)
            .expect("the policy decides after the deadline")
    }

    /// Returns true if the after-password path can change the result.
    /// Without a match or a reject, `allow` with `any` gives `PAM_IGNORE`
    /// whatever happens next. With `all`, an open result means that a
    /// factor still lacks a match.
    fn can_matter(&self) -> bool {
        self.settings.on_no_decision == OnNoDecision::Deny || self.settings.combine == Combine::All
    }

    fn conclude(&mut self, verdict: Verdict) -> i32 {
        if let Some(line) = conclusion(self.settings, verdict) {
            self.info(line);
        }
        verdict.outcome.exit_code()
    }

    fn deadline(&self) -> Instant {
        Instant::now() + Duration::from_secs(u64::from(self.settings.timeout_seconds))
    }

    /// Decides the step after the password.
    fn finish(mut self) -> i32 {
        // A result that the daemon held before the session counts, also
        // when `finish` comes right after the start of the session.
        let deadline = Instant::now() + FIRST_POLL_LIMIT;
        while self.settings.enabled(Factor::Face) && !self.polled.contains(&Factor::Face) {
            match self.next(Some(deadline)) {
                Next::Timeout => break,
                Next::End => return EXIT_NO_DECISION,
                Next::Handled | Next::Finish | Next::Answer(_) => {}
            }
        }
        if let Some(verdict) = self.settled() {
            return self.conclude(verdict);
        }
        if self.can_matter() {
            let line = format!("ask {}", self.finish_prompt);
            self.send(&line);
            let answer = loop {
                match self.next(None) {
                    Next::Answer(answer) => break answer,
                    Next::End => return EXIT_NO_DECISION,
                    Next::Handled | Next::Finish | Next::Timeout => {}
                }
            };
            if let Some(verdict) = self.settled() {
                return self.conclude(verdict);
            }
            if answer == Answer::Trigger && self.scan() {
                self.face_final = true;
                let deadline = self.deadline();
                return self.wait(deadline, false);
            }
        } else if self.settings.enabled(Factor::Face) && self.face.scanning() {
            self.face_final = true;
            let deadline = self.deadline();
            return self.wait(deadline, true);
        }
        let verdict = self.current();
        self.conclude(verdict)
    }

    /// Waits until the policy decides or `deadline` passes. With
    /// `face_only`, also ends when the face factor ends.
    fn wait(mut self, deadline: Instant, face_only: bool) -> i32 {
        loop {
            if let Some(verdict) = self.settings.decide(&self.finished, false) {
                return self.conclude(verdict);
            }
            if face_only && self.finished.contains_key(&Factor::Face) {
                let verdict = self.current();
                return self.conclude(verdict);
            }
            match self.next(Some(deadline)) {
                Next::Timeout => {
                    let verdict = self.current();
                    return self.conclude(verdict);
                }
                Next::End => return EXIT_NO_DECISION,
                Next::Handled | Next::Finish | Next::Answer(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    use pam_biometrics_policy::{EXIT_REJECT, EXIT_SUCCESS};

    use super::*;

    const BOTH: &[Factor] = &[Factor::Fingerprint, Factor::Face];
    const ASK: &str = "ask Touch the fingerprint reader, or press Enter to scan your face: ";

    /// A face daemon that records the scans.
    #[derive(Clone, Default)]
    struct FakeFace {
        scans: Arc<Mutex<u32>>,
        scanning: bool,
        refuse: bool,
    }

    impl FaceControl for FakeFace {
        fn scan(&mut self) -> bool {
            *self.scans.lock().unwrap() += 1;
            !self.refuse
        }

        fn scanning(&mut self) -> bool {
            self.scanning
        }
    }

    fn settings(combine: Combine, on_no_decision: OnNoDecision) -> Settings {
        Settings {
            factors: BOTH.to_vec(),
            combine,
            on_no_decision,
            timeout_seconds: 1,
            ..Settings::default()
        }
    }

    fn allow() -> Settings {
        settings(Combine::Any, OnNoDecision::Allow)
    }

    fn deny() -> Settings {
        settings(Combine::Any, OnNoDecision::Deny)
    }

    fn fingerprint(outcome: Outcome) -> Input {
        Input::Event(Event::Finished(Factor::Fingerprint, outcome))
    }

    fn face(outcome: Outcome) -> Input {
        if outcome == Outcome::Match {
            Input::Event(Event::Finished(Factor::Face, outcome))
        } else {
            Input::Event(Event::Provisional(Factor::Face, outcome))
        }
    }

    fn command(command: Command) -> Input {
        Input::Command(command)
    }

    /// Runs a session. Each input waits for its delay in milliseconds. The
    /// face factor has polled once before the inputs. Returns the exit
    /// code, the output lines, the number of scans, and the time.
    fn run(
        settings: &Settings,
        face_control: FakeFace,
        inputs: Vec<(u64, Input)>,
    ) -> (i32, Vec<String>, u32, Duration) {
        let mut all = vec![(0, Input::Event(Event::Polled(Factor::Face)))];
        all.extend(inputs);
        run_inputs(settings, face_control, all)
    }

    fn run_inputs(
        settings: &Settings,
        face_control: FakeFace,
        inputs: Vec<(u64, Input)>,
    ) -> (i32, Vec<String>, u32, Duration) {
        let (sender, receiver) = mpsc::channel();
        let feeder = thread::spawn(move || {
            for (delay, input) in inputs {
                thread::sleep(Duration::from_millis(delay));
                if sender.send(input).is_err() {
                    return;
                }
            }
            // Keep the channel open, as the stdin thread does.
            thread::sleep(FIRST_POLL_LIMIT + Duration::from_secs(1));
        });
        let scans = Arc::clone(&face_control.scans);
        let mut out = Vec::new();
        let start = Instant::now();
        let code = Session::new(
            settings,
            ASK.trim_start_matches("ask ").to_owned(),
            receiver,
            face_control,
            &mut out,
        )
        .run();
        let elapsed = start.elapsed();
        drop(feeder);
        let lines = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let scans = *scans.lock().unwrap();
        (code, lines, scans, elapsed)
    }

    #[test]
    fn commands_parse() {
        assert_eq!(Command::parse("scan"), Some(Command::Scan));
        assert_eq!(Command::parse("state\n"), Some(Command::State));
        assert_eq!(Command::parse("finish\r\n"), Some(Command::Finish));
        assert_eq!(
            Command::parse("answer trigger"),
            Some(Command::Answer(Answer::Trigger))
        );
        assert_eq!(
            Command::parse("answer other"),
            Some(Command::Answer(Answer::Other))
        );
        assert_eq!(Command::parse("stop"), Some(Command::Stop));
        for line in ["", "Scan", "scan now", "answer", "answer secret", " stop"] {
            assert_eq!(Command::parse(line), None, "{line:?}");
        }
    }

    #[test]
    fn password_only_with_allow_does_not_ask() {
        let (code, lines, scans, elapsed) = run(
            &allow(),
            FakeFace::default(),
            vec![(0, command(Command::Finish))],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert!(lines.is_empty(), "{lines:?}");
        assert_eq!(scans, 0);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn finish_waits_for_the_first_face_poll() {
        // The daemon held a match before the session started.
        let (code, lines, _, elapsed) = run_inputs(
            &allow(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (100, face(Outcome::Match)),
                (0, Input::Event(Event::Polled(Factor::Face))),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(lines, ["info Face recognized."]);
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");

        // Without a poll, the wait ends at its limit.
        let (code, _, _, elapsed) = run_inputs(
            &allow(),
            FakeFace::default(),
            vec![(0, command(Command::Finish))],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert!(elapsed >= FIRST_POLL_LIMIT, "{elapsed:?}");
    }

    #[test]
    fn finger_before_password() {
        let (code, lines, _, elapsed) = run(
            &deny(),
            FakeFace::default(),
            vec![
                (
                    0,
                    Input::Event(Event::Message(
                        "Fingerprint not recognized. Try again.".to_owned(),
                    )),
                ),
                (0, fingerprint(Outcome::Match)),
                (50, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(
            lines,
            [
                "info Fingerprint not recognized. Try again.",
                "info Fingerprint recognized."
            ]
        );
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn finger_after_password_with_deny() {
        let (code, lines, scans, _) = run(
            &deny(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (50, fingerprint(Outcome::Match)),
                (50, command(Command::Answer(Answer::Other))),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(lines, [ASK, "info Fingerprint recognized."]);
        // A match before the response needs no face scan.
        assert_eq!(scans, 0);
    }

    #[test]
    fn finger_during_the_face_wait() {
        let (code, lines, scans, _) = run(
            &deny(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (0, command(Command::Answer(Answer::Trigger))),
                (100, fingerprint(Outcome::Match)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(lines, [ASK, "info Fingerprint recognized."]);
        assert_eq!(scans, 1);
    }

    #[test]
    fn face_before_password() {
        let (code, lines, scans, _) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, command(Command::Scan)),
                (50, face(Outcome::Match)),
                (50, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(lines, ["info Face recognized."]);
        assert_eq!(scans, 1);
    }

    #[test]
    fn repeated_triggers_start_repeated_scans() {
        let (_, _, scans, _) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, command(Command::Scan)),
                (0, command(Command::Scan)),
                (0, command(Command::Scan)),
                (0, command(Command::Stop)),
            ],
        );
        assert_eq!(scans, 3);
    }

    #[test]
    fn face_after_password_with_deny() {
        let (code, lines, scans, elapsed) = run(
            &deny(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (0, command(Command::Answer(Answer::Trigger))),
                (100, face(Outcome::Match)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(lines, [ASK, "info Face recognized."]);
        assert_eq!(scans, 1);
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
    }

    #[test]
    fn other_response_with_deny_rejects_at_once() {
        let (code, lines, scans, elapsed) = run(
            &deny(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (0, command(Command::Answer(Answer::Other))),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(lines, [ASK, "info A fingerprint or a face is necessary."]);
        assert_eq!(scans, 0);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn face_without_a_match_waits_for_the_finger_until_the_timeout() {
        let (code, lines, _, elapsed) = run(
            &deny(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (0, command(Command::Answer(Answer::Trigger))),
                (
                    50,
                    Input::Event(Event::Message("No face found.".to_owned())),
                ),
                (0, face(Outcome::NoDecision)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(
            lines,
            [
                ASK,
                "info No face found.",
                "info A fingerprint or a face is necessary."
            ]
        );
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn face_only_decides_on_the_scan_result() {
        let mut face_only = deny();
        face_only.factors = vec![Factor::Face];
        let (code, lines, _, elapsed) = run(
            &face_only,
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (0, command(Command::Answer(Answer::Trigger))),
                (50, face(Outcome::NoDecision)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(lines.last().unwrap(), "info A face is necessary.");
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
    }

    #[test]
    fn a_refused_scan_ends_without_a_wait() {
        let refuse = FakeFace {
            refuse: true,
            ..FakeFace::default()
        };
        let (code, lines, scans, elapsed) = run(
            &deny(),
            refuse,
            vec![
                (0, command(Command::Finish)),
                (0, command(Command::Answer(Answer::Trigger))),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(
            lines,
            [
                ASK,
                "info The face scan did not start.",
                "info A fingerprint or a face is necessary."
            ]
        );
        assert_eq!(scans, 1);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn wrong_finger_rejects_at_once() {
        let (code, lines, _, elapsed) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, fingerprint(Outcome::Reject)),
                (0, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(lines, ["info Not recognized."]);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn face_reject_before_password_rejects() {
        let (code, lines, _, _) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (
                    0,
                    Input::Event(Event::Message("Face not recognized.".to_owned())),
                ),
                (0, face(Outcome::Reject)),
                (0, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(lines, ["info Face not recognized.", "info Not recognized."]);
    }

    #[test]
    fn a_later_match_replaces_a_face_reject() {
        let (code, _, _, _) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, face(Outcome::Reject)),
                (0, fingerprint(Outcome::Match)),
                (0, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
    }

    #[test]
    fn allow_waits_only_for_a_running_scan() {
        let scanning = FakeFace {
            scanning: true,
            ..FakeFace::default()
        };
        let (code, lines, scans, elapsed) = run(
            &allow(),
            scanning.clone(),
            vec![(0, command(Command::Finish)), (100, face(Outcome::Match))],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(lines, ["info Face recognized."]);
        assert_eq!(scans, 0);
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");

        // A scan without a face ends the wait. The finger does not count
        // any more: it cannot change PAM_IGNORE.
        let (code, _, _, elapsed) = run(
            &allow(),
            scanning.clone(),
            vec![
                (0, command(Command::Finish)),
                (100, face(Outcome::NoDecision)),
            ],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");

        // Without a result, the wait ends at the timeout.
        let (code, _, _, elapsed) = run(&allow(), scanning, vec![(0, command(Command::Finish))]);
        assert_eq!(code, EXIT_NO_DECISION);
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn all_asks_for_the_missing_factor() {
        let all = settings(Combine::All, OnNoDecision::Allow);
        let (code, lines, scans, _) = run(
            &all,
            FakeFace::default(),
            vec![
                (0, fingerprint(Outcome::Match)),
                (0, command(Command::Finish)),
                (50, command(Command::Answer(Answer::Trigger))),
                (50, face(Outcome::Match)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(
            lines,
            ["info Fingerprint recognized.", ASK, "info Face recognized."]
        );
        assert_eq!(scans, 1);
    }

    #[test]
    fn all_rejects_on_a_face_reject() {
        let all = settings(Combine::All, OnNoDecision::Allow);
        let (code, _, _, elapsed) = run(
            &all,
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (0, command(Command::Answer(Answer::Trigger))),
                (50, face(Outcome::Reject)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
    }

    #[test]
    fn stop_and_close_give_no_decision() {
        for end in [command(Command::Stop), Input::Closed] {
            let (code, _, _, _) = run(&deny(), FakeFace::default(), vec![(0, end.clone())]);
            assert_eq!(code, EXIT_NO_DECISION);
            // An abort during the prompt of finish.
            let (code, lines, _, _) = run(
                &deny(),
                FakeFace::default(),
                vec![(0, command(Command::Finish)), (0, end)],
            );
            assert_eq!(code, EXIT_NO_DECISION);
            assert_eq!(lines, [ASK]);
        }
    }

    #[test]
    fn state_reports_the_verdict_and_the_scan() {
        let scanning = FakeFace {
            scanning: true,
            ..FakeFace::default()
        };
        let (_, lines, _, _) = run(
            &allow(),
            scanning,
            vec![
                (0, command(Command::State)),
                (0, fingerprint(Outcome::Match)),
                (0, command(Command::State)),
                (0, command(Command::Stop)),
            ],
        );
        assert_eq!(
            lines,
            [
                "state pending scanning",
                "info Fingerprint recognized.",
                "state success scanning"
            ]
        );
        let (_, lines, _, _) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, fingerprint(Outcome::Reject)),
                (0, command(Command::State)),
                (0, command(Command::Stop)),
            ],
        );
        assert_eq!(lines, ["state reject idle"]);
    }

    #[test]
    fn conclusions() {
        let verdict = |combined, outcome| Verdict { combined, outcome };
        let mut all = settings(Combine::All, OnNoDecision::Deny);
        assert_eq!(
            conclusion(&all, verdict(Outcome::Match, StepOutcome::Success)),
            None
        );
        assert_eq!(
            conclusion(&all, verdict(Outcome::Reject, StepOutcome::Reject)),
            Some("Not recognized.")
        );
        assert_eq!(
            conclusion(&all, verdict(Outcome::NoDecision, StepOutcome::Reject)),
            Some("A fingerprint and a face are necessary.")
        );
        all.factors = vec![Factor::Fingerprint];
        assert_eq!(
            conclusion(&all, verdict(Outcome::NoDecision, StepOutcome::Reject)),
            Some("A fingerprint is necessary.")
        );
        assert_eq!(
            conclusion(
                &allow(),
                verdict(Outcome::NoDecision, StepOutcome::NoDecision)
            ),
            None
        );
    }

    #[test]
    fn pause_ends_early_when_stopped() {
        let start = Instant::now();
        assert!(pause(Duration::from_millis(50), || false));
        assert!(start.elapsed() >= Duration::from_millis(50));
        let start = Instant::now();
        assert!(!pause(Duration::from_secs(5), || true));
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
