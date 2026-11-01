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
    Combine, EXIT_NO_DECISION, Factor, Outcome, Settings, StepOutcome, Verdict,
};

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
    wait_message: String,
    /// The text of the `ask` line with `after_password: prompt`.
    ask: Option<String>,
    inputs: Receiver<Input>,
    face: F,
    out: W,
    /// The outcome of each factor that ended.
    finished: BTreeMap<Factor, Outcome>,
    /// The last outcome of each factor that still runs.
    provisional: BTreeMap<Factor, Outcome>,
    /// The factors that asked their source at least once.
    polled: BTreeSet<Factor>,
}

impl<'a, F: FaceControl, W: Write> Session<'a, F, W> {
    /// Creates a session. `finish` shows `wait_message` when it waits.
    /// With `ask`, `finish` first asks the module to prompt with that text.
    pub fn new(
        settings: &'a Settings,
        wait_message: String,
        ask: Option<String>,
        inputs: Receiver<Input>,
        face: F,
        out: W,
    ) -> Self {
        Self {
            settings,
            wait_message,
            ask,
            inputs,
            face,
            out,
            finished: BTreeMap::new(),
            provisional: BTreeMap::new(),
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
            Input::Command(Command::Scan) => self.scan(),
            Input::Command(Command::State) => self.report_state(),
            Input::Command(Command::Finish) => return Next::Finish,
            Input::Command(Command::Answer(answer)) => return Next::Answer(answer),
            Input::Command(Command::Stop) | Input::Closed => return Next::End,
        }
        Next::Handled
    }

    /// Returns true once a factor rejected. The attempt then fails.
    fn rejected(&self) -> bool {
        self.finished
            .values()
            .any(|outcome| *outcome == Outcome::Reject)
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Message(text) => self.info(&text),
            Event::Polled(factor) => {
                self.polled.insert(factor);
            }
            // A reject sticks for the whole session: no later result of
            // any factor replaces it.
            Event::Provisional(factor, Outcome::Reject)
            | Event::Finished(factor, Outcome::Reject) => {
                self.finished.insert(factor, Outcome::Reject);
            }
            Event::Provisional(factor, outcome) => {
                self.provisional.insert(factor, outcome);
            }
            Event::Finished(factor, outcome) => {
                if self.finished.get(&factor) == Some(&Outcome::Reject) {
                    return;
                }
                // After a reject, a match changes nothing, so it shows
                // nothing.
                if outcome == Outcome::Match && !self.rejected() {
                    self.info(recognized(factor));
                }
                self.finished.insert(factor, outcome);
            }
        }
    }

    /// Starts a face scan.
    fn scan(&mut self) {
        if self.settings.enabled(Factor::Face) && !self.face.scan() {
            self.info("The face scan did not start.");
        }
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

    fn conclude(&mut self, verdict: Verdict) -> i32 {
        if let Some(line) = conclusion(self.settings, verdict) {
            self.info(line);
        }
        verdict.outcome.exit_code()
    }

    /// Decides the step after the password. A match or a reject so far
    /// decides at once. Otherwise, with `after_password: prompt`, `finish`
    /// asks once and waits for the answer. The face trigger as the answer
    /// starts a face scan, any other answer shows the wait message. With
    /// `after_password: wait`, `finish` shows the wait message at once.
    /// Then it waits for a match or a reject until `timeout_seconds` after
    /// its start. Without one, `on_no_decision` applies.
    fn finish(mut self) -> i32 {
        let deadline =
            Instant::now() + Duration::from_secs(u64::from(self.settings.timeout_seconds));
        // A result that the daemon held before the session counts, also
        // when `finish` comes right after the start of the session.
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
        let answer = match self.ask.clone() {
            Some(prompt) => {
                self.send(&format!("ask {prompt}"));
                // The prompt blocks the module until the user answers. The
                // factors still count meanwhile.
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
                answer
            }
            None => Answer::Other,
        };
        if answer == Answer::Trigger && self.settings.enabled(Factor::Face) {
            self.scan();
        } else {
            let message = self.wait_message.clone();
            self.info(&message);
        }
        loop {
            match self.next(Some(deadline)) {
                Next::Timeout => {
                    let verdict = self.current();
                    return self.conclude(verdict);
                }
                Next::End => return EXIT_NO_DECISION,
                Next::Handled | Next::Finish | Next::Answer(_) => {}
            }
            if let Some(verdict) = self.settled() {
                return self.conclude(verdict);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    use pam_biometrics_policy::{AfterPassword, EXIT_REJECT, EXIT_SUCCESS, OnNoDecision};

    use super::*;

    const BOTH: &[Factor] = &[Factor::Fingerprint, Factor::Face];
    const WAIT: &str = "Touch the fingerprint reader or press Enter to scan your face (1 s).";
    const INFO_WAIT: &str =
        "info Touch the fingerprint reader or press Enter to scan your face (1 s).";
    const ASK: &str =
        "Touch the fingerprint reader or press Enter to scan your face (other text skips): ";
    const ASK_LINE: &str =
        "ask Touch the fingerprint reader or press Enter to scan your face (other text skips): ";

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

    fn prompt(on_no_decision: OnNoDecision) -> Settings {
        Settings {
            after_password: AfterPassword::Prompt,
            ..settings(Combine::Any, on_no_decision)
        }
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

    fn message(text: &str) -> Input {
        Input::Event(Event::Message(text.to_owned()))
    }

    fn command(command: Command) -> Input {
        Input::Command(command)
    }

    /// Runs a session. Each input waits for its delay in milliseconds. The
    /// face factor has polled once before the inputs. Returns the exit
    /// code, the output lines, the number of scans, and the time from the
    /// start of the session.
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
            thread::sleep(Duration::from_secs(3));
        });
        let scans = Arc::clone(&face_control.scans);
        let mut out = Vec::new();
        let start = Instant::now();
        // The helper derives the text from the policy. Any text works here.
        let ask = (settings.after_password == AfterPassword::Prompt).then(|| ASK.to_owned());
        let code = Session::new(
            settings,
            WAIT.to_owned(),
            ask,
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
        assert_eq!(Command::parse("stop"), Some(Command::Stop));
        assert_eq!(
            Command::parse("answer trigger"),
            Some(Command::Answer(Answer::Trigger))
        );
        assert_eq!(
            Command::parse("answer other"),
            Some(Command::Answer(Answer::Other))
        );
        for line in ["", "Scan", "scan now", "answer", "answer secret", " stop"] {
            assert_eq!(Command::parse(line), None, "{line:?}");
        }
    }

    #[test]
    fn prompt_trigger_scans_then_a_match_succeeds() {
        let (code, lines, scans, elapsed) = run(
            &prompt(OnNoDecision::Allow),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (50, command(Command::Answer(Answer::Trigger))),
                (100, face(Outcome::Match)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        // The scan replaces the wait message.
        assert_eq!(lines, [ASK_LINE, "info Face recognized."]);
        assert_eq!(scans, 1);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn prompt_trigger_then_the_finger_still_counts() {
        let (code, _, scans, _) = run(
            &prompt(OnNoDecision::Deny),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (0, command(Command::Answer(Answer::Trigger))),
                (100, face(Outcome::NoDecision)),
                (100, fingerprint(Outcome::Match)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(scans, 1);
    }

    #[test]
    fn prompt_other_answer_waits_until_the_timeout() {
        for (on_no_decision, want) in [
            (OnNoDecision::Allow, EXIT_NO_DECISION),
            (OnNoDecision::Deny, EXIT_REJECT),
        ] {
            let (code, lines, scans, elapsed) = run(
                &prompt(on_no_decision),
                FakeFace::default(),
                vec![
                    (0, command(Command::Finish)),
                    (0, command(Command::Answer(Answer::Other))),
                ],
            );
            assert_eq!(code, want);
            assert_eq!(lines[..2], [ASK_LINE, INFO_WAIT]);
            assert_eq!(scans, 0);
            assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
        }
    }

    #[test]
    fn prompt_timeout_counts_from_the_start_of_finish() {
        // The user answers late. The wait ends at once.
        let (code, lines, _, elapsed) = run(
            &prompt(OnNoDecision::Allow),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (1200, command(Command::Answer(Answer::Other))),
            ],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert_eq!(lines, [ASK_LINE, INFO_WAIT]);
        assert!(elapsed < Duration::from_millis(1600), "{elapsed:?}");
    }

    #[test]
    fn prompt_finger_during_the_prompt_decides_after_the_answer() {
        let (code, lines, scans, elapsed) = run(
            &prompt(OnNoDecision::Deny),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (50, fingerprint(Outcome::Match)),
                (50, command(Command::Answer(Answer::Trigger))),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(lines, [ASK_LINE, "info Fingerprint recognized."]);
        // The match came first, so the trigger starts no scan.
        assert_eq!(scans, 0);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn prompt_reject_during_the_prompt_rejects() {
        let (code, lines, _, elapsed) = run(
            &prompt(OnNoDecision::Allow),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (50, fingerprint(Outcome::Reject)),
                (50, command(Command::Answer(Answer::Other))),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(lines, [ASK_LINE, "info Not recognized."]);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn prompt_is_skipped_after_a_decision() {
        let (code, lines, _, _) = run(
            &prompt(OnNoDecision::Deny),
            FakeFace::default(),
            vec![
                (0, fingerprint(Outcome::Match)),
                (0, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(lines, ["info Fingerprint recognized."]);
    }

    #[test]
    fn prompt_abort_gives_no_decision() {
        let (code, lines, _, _) = run(
            &prompt(OnNoDecision::Deny),
            FakeFace::default(),
            vec![(0, command(Command::Finish)), (50, command(Command::Stop))],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert_eq!(lines, [ASK_LINE]);
    }

    #[test]
    fn allow_without_a_factor_waits_then_gives_no_decision() {
        let (code, lines, scans, elapsed) = run(
            &allow(),
            FakeFace::default(),
            vec![(0, command(Command::Finish))],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert_eq!(lines, [INFO_WAIT]);
        assert_eq!(scans, 0);
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
    }

    #[test]
    fn deny_without_a_factor_waits_then_rejects() {
        let (code, lines, _, elapsed) = run(
            &deny(),
            FakeFace::default(),
            vec![(0, command(Command::Finish))],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(
            lines,
            [INFO_WAIT, "info A fingerprint or a face is necessary."]
        );
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn the_timeout_counts_from_the_start_of_finish() {
        let (code, _, _, elapsed) = run(
            &allow(),
            FakeFace::default(),
            vec![(500, command(Command::Finish))],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert!(elapsed >= Duration::from_millis(1500), "{elapsed:?}");
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
        // A decision before the wait shows no wait message.
        assert_eq!(lines, ["info Face recognized."]);
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");

        // Without a poll, the timeout still ends the wait.
        let (code, lines, _, elapsed) = run_inputs(
            &allow(),
            FakeFace::default(),
            vec![(0, command(Command::Finish))],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert_eq!(lines, [INFO_WAIT]);
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn finger_before_password() {
        let (code, lines, _, elapsed) = run(
            &deny(),
            FakeFace::default(),
            vec![
                (0, message("Fingerprint not recognized. Try again.")),
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
    fn match_during_the_wait_succeeds_at_once() {
        for on_no_decision in [OnNoDecision::Allow, OnNoDecision::Deny] {
            let (code, lines, _, elapsed) = run(
                &settings(Combine::Any, on_no_decision),
                FakeFace::default(),
                vec![
                    (0, command(Command::Finish)),
                    (100, fingerprint(Outcome::Match)),
                ],
            );
            assert_eq!(code, EXIT_SUCCESS);
            assert_eq!(lines, [INFO_WAIT, "info Fingerprint recognized."]);
            assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
        }
    }

    #[test]
    fn face_scan_during_the_wait() {
        let (code, lines, scans, elapsed) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (50, command(Command::Scan)),
                (100, face(Outcome::Match)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(lines, [INFO_WAIT, "info Face recognized."]);
        assert_eq!(scans, 1);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn reject_during_the_wait_fails_at_once() {
        // A wrong finger.
        let (code, lines, _, elapsed) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (100, fingerprint(Outcome::Reject)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(lines, [INFO_WAIT, "info Not recognized."]);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");

        // A face beyond the reject distance.
        let (code, lines, _, elapsed) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (100, message("Face not recognized.")),
                (0, face(Outcome::Reject)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(
            lines,
            [
                INFO_WAIT,
                "info Face not recognized.",
                "info Not recognized."
            ]
        );
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn an_uncertain_face_during_the_wait_keeps_waiting() {
        let (code, lines, _, elapsed) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (100, message("Face not certain. Scan again.")),
                (0, face(Outcome::NoDecision)),
            ],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert_eq!(lines, [INFO_WAIT, "info Face not certain. Scan again."]);
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");

        // A second scan in the wait can still match.
        let (code, _, _, elapsed) = run(
            &deny(),
            FakeFace::default(),
            vec![
                (0, command(Command::Finish)),
                (100, face(Outcome::NoDecision)),
                (300, face(Outcome::Match)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
    }

    #[test]
    fn rejects_before_the_password_fail_at_once() {
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

        let (code, lines, _, _) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, message("Face not recognized.")),
                (0, face(Outcome::Reject)),
                (0, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(lines, ["info Face not recognized.", "info Not recognized."]);
    }

    #[test]
    fn a_face_reject_sticks() {
        for combine in [Combine::Any, Combine::All] {
            let policy = settings(combine, OnNoDecision::Allow);
            // Reject, then no face.
            let (code, lines, _, elapsed) = run(
                &policy,
                FakeFace::default(),
                vec![
                    (0, message("Face not recognized.")),
                    (0, face(Outcome::Reject)),
                    (0, message("No face found.")),
                    (0, face(Outcome::NoDecision)),
                    (0, command(Command::Finish)),
                ],
            );
            assert_eq!(code, EXIT_REJECT, "{combine:?}");
            assert_eq!(
                lines,
                [
                    "info Face not recognized.",
                    "info No face found.",
                    "info Not recognized."
                ]
            );
            assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");

            // Reject, then a face match. The match shows nothing.
            let (code, lines, _, _) = run(
                &policy,
                FakeFace::default(),
                vec![
                    (0, face(Outcome::Reject)),
                    (0, face(Outcome::Match)),
                    (0, command(Command::Finish)),
                ],
            );
            assert_eq!(code, EXIT_REJECT, "{combine:?}");
            assert_eq!(lines, ["info Not recognized."]);

            // Reject, then a fingerprint match, and a could-match face.
            let (code, _, _, _) = run(
                &policy,
                FakeFace::default(),
                vec![
                    (0, face(Outcome::Reject)),
                    (0, fingerprint(Outcome::Match)),
                    (0, face(Outcome::NoDecision)),
                    (0, command(Command::Finish)),
                ],
            );
            assert_eq!(code, EXIT_REJECT, "{combine:?}");
        }
    }

    #[test]
    fn a_wrong_finger_sticks() {
        let (code, lines, _, _) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, fingerprint(Outcome::Reject)),
                (0, face(Outcome::Match)),
                (0, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(lines, ["info Not recognized."]);
    }

    #[test]
    fn a_reject_after_a_match_fails() {
        // A match before the password and a reject later in the session.
        let (code, lines, _, _) = run(
            &allow(),
            FakeFace::default(),
            vec![
                (0, fingerprint(Outcome::Match)),
                (0, face(Outcome::Reject)),
                (0, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(
            lines,
            ["info Fingerprint recognized.", "info Not recognized."]
        );
    }

    #[test]
    fn repeated_scans() {
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
    fn a_refused_scan_says_so() {
        let refuse = FakeFace {
            refuse: true,
            ..FakeFace::default()
        };
        let (_, lines, scans, _) = run(
            &allow(),
            refuse,
            vec![(0, command(Command::Scan)), (0, command(Command::Stop))],
        );
        assert_eq!(lines, ["info The face scan did not start."]);
        assert_eq!(scans, 1);
    }

    #[test]
    fn without_the_face_factor_scans_do_nothing() {
        let mut finger = allow();
        finger.factors = vec![Factor::Fingerprint];
        let (_, lines, scans, _) = run(
            &finger,
            FakeFace::default(),
            vec![(0, command(Command::Scan)), (0, command(Command::Stop))],
        );
        assert!(lines.is_empty(), "{lines:?}");
        assert_eq!(scans, 0);
    }

    #[test]
    fn all_waits_for_the_missing_factor() {
        let all = settings(Combine::All, OnNoDecision::Allow);
        let (code, lines, _, elapsed) = run(
            &all,
            FakeFace::default(),
            vec![
                (0, fingerprint(Outcome::Match)),
                (0, command(Command::Finish)),
                (100, face(Outcome::Match)),
            ],
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(
            lines,
            [
                "info Fingerprint recognized.",
                INFO_WAIT,
                "info Face recognized."
            ]
        );
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");

        let (code, lines, _, _) = run(
            &all,
            FakeFace::default(),
            vec![
                (0, fingerprint(Outcome::Match)),
                (0, command(Command::Finish)),
            ],
        );
        assert_eq!(code, EXIT_NO_DECISION);
        assert_eq!(lines, ["info Fingerprint recognized.", INFO_WAIT]);
    }

    #[test]
    fn all_rejects_on_a_face_reject() {
        let all = settings(Combine::All, OnNoDecision::Allow);
        let (code, _, _, elapsed) = run(
            &all,
            FakeFace::default(),
            vec![
                (0, fingerprint(Outcome::Match)),
                (0, command(Command::Finish)),
                (50, face(Outcome::Reject)),
                (0, face(Outcome::NoDecision)),
            ],
        );
        assert_eq!(code, EXIT_REJECT);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn stop_and_close_give_no_decision() {
        for end in [command(Command::Stop), Input::Closed] {
            let (code, _, _, _) = run(&deny(), FakeFace::default(), vec![(0, end.clone())]);
            assert_eq!(code, EXIT_NO_DECISION);
            // An abort during the wait of finish.
            let (code, lines, _, elapsed) = run(
                &deny(),
                FakeFace::default(),
                vec![(0, command(Command::Finish)), (50, end)],
            );
            assert_eq!(code, EXIT_NO_DECISION);
            assert_eq!(lines, [INFO_WAIT]);
            assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
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
