//! The PAM helper: `pam_biometrics.so` runs `pam-biometrics pam-helper`.

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use pam_biometrics_policy::{
    Combine, EXIT_NO_DECISION, Factor, Outcome, Policy, Settings, StepOutcome,
};

use crate::face::{Daemon, FaceTask};
use crate::fingerprint::FingerprintTask;
use crate::step::{self, FactorTask, StepResult};

/// The prompt when both factors are enabled and nothing else sets it.
pub const DEFAULT_PROMPT: &str = "Touch the fingerprint reader or scan your face.";

/// Returns the line that the step shows when it starts to wait.
#[must_use]
pub fn prompt(settings: &Settings, flag: Option<&str>) -> Option<String> {
    if settings.factors.is_empty() {
        return None;
    }
    if let Some(prompt) = flag.or(settings.prompt.as_deref()) {
        return Some(prompt.to_owned());
    }
    let text = match (
        settings.enabled(Factor::Fingerprint),
        settings.enabled(Factor::Face),
    ) {
        (true, true) => DEFAULT_PROMPT,
        (true, false) => "Touch the fingerprint reader.",
        _ => "Scan your face.",
    };
    Some(text.to_owned())
}

/// Returns the line that the step shows after the decision.
#[must_use]
pub fn conclusion(settings: &Settings, result: &StepResult) -> Option<String> {
    match result.verdict.combined {
        Outcome::Match => {
            let lines: Vec<&str> = settings
                .factors
                .iter()
                .filter(|factor| result.finished.get(factor) == Some(&Outcome::Match))
                .map(|factor| match factor {
                    Factor::Fingerprint => "Fingerprint recognized.",
                    Factor::Face => "Face recognized.",
                })
                .collect();
            Some(lines.join("\n"))
        }
        Outcome::Reject => Some("Not recognized.".to_owned()),
        Outcome::NoDecision if result.verdict.outcome == StepOutcome::Reject => {
            let fingerprint = settings.enabled(Factor::Fingerprint);
            let face = settings.enabled(Factor::Face);
            Some(
                match (fingerprint, face, settings.combine) {
                    (true, true, Combine::Any) => "A fingerprint or a face is necessary.",
                    (true, true, Combine::All) => "A fingerprint and a face are necessary.",
                    (true, false, _) => "A fingerprint is necessary.",
                    _ => "A face is necessary.",
                }
                .to_owned(),
            )
        }
        Outcome::NoDecision => None,
    }
}

/// Runs the step with `tasks` and writes the user-facing lines to `out`.
/// Returns the helper exit code.
pub fn decide(
    settings: &Settings,
    tasks: Vec<Box<dyn FactorTask>>,
    prompt_flag: Option<&str>,
    out: &mut dyn Write,
) -> i32 {
    if settings.factors.is_empty() {
        return EXIT_NO_DECISION;
    }
    if let Some(prompt) = prompt(settings, prompt_flag) {
        let _ = writeln!(out, "{prompt}");
        let _ = out.flush();
    }
    let timeout = Duration::from_secs(u64::from(settings.timeout_seconds));
    let result = step::run(settings, tasks, timeout, out);
    if let Some(line) = conclusion(settings, &result) {
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
    result.verdict.outcome.exit_code()
}

/// The PAM environment of the helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PamEnv {
    /// `PAM_USER`.
    pub user: String,
    /// `PAM_SERVICE`, if set.
    pub service: Option<String>,
}

impl PamEnv {
    /// Reads the environment. Returns `None` outside an auth call or
    /// without a user.
    #[must_use]
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let var = |name: &str| var(name).filter(|value| !value.is_empty());
        if var("PAM_TYPE").as_deref() != Some("auth") {
            return None;
        }
        Some(Self {
            user: var("PAM_USER")?,
            service: var("PAM_SERVICE"),
        })
    }
}

/// Runs the helper for the PAM environment of the process.
pub fn run(policy_path: &Path, socket: &Path, prompt_flag: Option<&str>) -> i32 {
    let Some(env) = PamEnv::from_vars(|name| std::env::var(name).ok()) else {
        return EXIT_NO_DECISION;
    };
    let policy = match Policy::load(policy_path) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("pam-biometrics: {error}");
            return EXIT_NO_DECISION;
        }
    };
    let settings = policy.resolve(env.service.as_deref(), Some(&env.user));
    let deadline = Instant::now() + Duration::from_secs(u64::from(settings.timeout_seconds));
    let tasks: Vec<Box<dyn FactorTask>> = settings
        .factors
        .iter()
        .map(|factor| -> Box<dyn FactorTask> {
            match factor {
                Factor::Fingerprint => Box::new(FingerprintTask {
                    user: env.user.clone(),
                    max_tries: settings.fingerprint.max_tries,
                }),
                Factor::Face => Box::new(FaceTask {
                    source: Daemon {
                        socket: socket.to_owned(),
                        user: env.user.clone(),
                    },
                    face: settings.face.clone(),
                    deadline,
                }),
            }
        })
        .collect();
    decide(&settings, tasks, prompt_flag, &mut std::io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::mpsc::Sender;
    use std::thread;

    use pam_biometrics_policy::{EXIT_REJECT, EXIT_SUCCESS, OnNoDecision, Verdict};

    use super::*;
    use crate::fingerprint::RETRY_MESSAGE;
    use crate::step::{Event, Stop};

    struct Script(Vec<Event>);

    struct NoStop;

    impl Stop for NoStop {
        fn stop(self: Box<Self>) {}
    }

    impl FactorTask for Script {
        fn start(self: Box<Self>, events: Sender<Event>) -> Box<dyn Stop> {
            thread::spawn(move || {
                for event in self.0 {
                    let _ = events.send(event);
                }
            });
            Box::new(NoStop)
        }
    }

    fn settings(factors: &[Factor]) -> Settings {
        Settings {
            factors: factors.to_vec(),
            timeout_seconds: 2,
            ..Settings::default()
        }
    }

    fn run_script(
        settings: &Settings,
        scripts: Vec<Vec<Event>>,
        flag: Option<&str>,
    ) -> (i32, String) {
        let tasks = scripts
            .into_iter()
            .map(|script| Box::new(Script(script)) as Box<dyn FactorTask>)
            .collect();
        let mut out = Vec::new();
        let code = decide(settings, tasks, flag, &mut out);
        (code, String::from_utf8(out).unwrap())
    }

    const BOTH: &[Factor] = &[Factor::Fingerprint, Factor::Face];

    #[test]
    fn prompts() {
        assert_eq!(
            prompt(&settings(BOTH), None).as_deref(),
            Some(DEFAULT_PROMPT)
        );
        assert_eq!(
            prompt(&settings(&[Factor::Fingerprint]), None).as_deref(),
            Some("Touch the fingerprint reader.")
        );
        assert_eq!(
            prompt(&settings(&[Factor::Face]), None).as_deref(),
            Some("Scan your face.")
        );
        assert_eq!(prompt(&settings(&[]), Some("ignored")), None);

        let mut custom = settings(BOTH);
        custom.prompt = Some("Touch the fingerprint reader or press Super+Alt+F.".to_owned());
        assert_eq!(
            prompt(&custom, None).as_deref(),
            Some("Touch the fingerprint reader or press Super+Alt+F.")
        );
        assert_eq!(
            prompt(&custom, Some("From the flag.")).as_deref(),
            Some("From the flag.")
        );
    }

    #[test]
    fn fingerprint_match() {
        let (code, out) = run_script(
            &settings(BOTH),
            vec![
                vec![
                    Event::Message(RETRY_MESSAGE.to_owned()),
                    Event::Finished(Factor::Fingerprint, Outcome::Match),
                ],
                vec![],
            ],
            None,
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(
            out,
            format!("{DEFAULT_PROMPT}\n{RETRY_MESSAGE}\nFingerprint recognized.\n")
        );
    }

    #[test]
    fn face_match() {
        let (code, out) = run_script(
            &settings(BOTH),
            vec![
                vec![Event::Finished(Factor::Fingerprint, Outcome::NoDecision)],
                vec![Event::Finished(Factor::Face, Outcome::Match)],
            ],
            None,
        );
        assert_eq!(code, EXIT_SUCCESS);
        assert_eq!(out, format!("{DEFAULT_PROMPT}\nFace recognized.\n"));
    }

    #[test]
    fn reject() {
        let (code, out) = run_script(
            &settings(BOTH),
            vec![
                vec![Event::Finished(Factor::Fingerprint, Outcome::Reject)],
                vec![Event::Finished(Factor::Face, Outcome::NoDecision)],
            ],
            Some("Prompt."),
        );
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(out, "Prompt.\nNot recognized.\n");
    }

    #[test]
    fn no_decision_allow_and_deny() {
        let unavailable = || {
            vec![
                vec![Event::Finished(Factor::Fingerprint, Outcome::NoDecision)],
                vec![Event::Finished(Factor::Face, Outcome::NoDecision)],
            ]
        };
        let (code, out) = run_script(&settings(BOTH), unavailable(), None);
        assert_eq!(code, EXIT_NO_DECISION);
        assert_eq!(out, format!("{DEFAULT_PROMPT}\n"));

        let mut deny = settings(BOTH);
        deny.on_no_decision = OnNoDecision::Deny;
        let (code, out) = run_script(&deny, unavailable(), None);
        assert_eq!(code, EXIT_REJECT);
        assert_eq!(
            out,
            format!("{DEFAULT_PROMPT}\nA fingerprint or a face is necessary.\n")
        );
    }

    #[test]
    fn empty_factors_print_nothing() {
        let (code, out) = run_script(&settings(&[]), vec![], None);
        assert_eq!(code, EXIT_NO_DECISION);
        assert_eq!(out, "");
    }

    #[test]
    fn conclusion_for_all() {
        let mut all = settings(BOTH);
        all.combine = Combine::All;
        let both: BTreeMap<Factor, Outcome> = [
            (Factor::Fingerprint, Outcome::Match),
            (Factor::Face, Outcome::Match),
        ]
        .into();
        let result = StepResult {
            verdict: Verdict {
                combined: Outcome::Match,
                outcome: StepOutcome::Success,
            },
            finished: both,
        };
        assert_eq!(
            conclusion(&all, &result).as_deref(),
            Some("Fingerprint recognized.\nFace recognized.")
        );
        all.on_no_decision = OnNoDecision::Deny;
        let denied = StepResult {
            verdict: Verdict {
                combined: Outcome::NoDecision,
                outcome: StepOutcome::Reject,
            },
            finished: BTreeMap::new(),
        };
        assert_eq!(
            conclusion(&all, &denied).as_deref(),
            Some("A fingerprint and a face are necessary.")
        );
    }

    #[test]
    fn environment() {
        let vars = |pairs: &[(&str, &str)]| {
            let map: HashMap<String, String> = pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect();
            PamEnv::from_vars(move |name| map.get(name).cloned())
        };
        assert_eq!(
            vars(&[
                ("PAM_TYPE", "auth"),
                ("PAM_USER", "alice"),
                ("PAM_SERVICE", "sudo")
            ]),
            Some(PamEnv {
                user: "alice".to_owned(),
                service: Some("sudo".to_owned())
            })
        );
        assert_eq!(
            vars(&[("PAM_TYPE", "auth"), ("PAM_USER", "alice")]),
            Some(PamEnv {
                user: "alice".to_owned(),
                service: None
            })
        );
        assert_eq!(
            vars(&[("PAM_TYPE", "account"), ("PAM_USER", "alice")]),
            None
        );
        assert_eq!(vars(&[("PAM_USER", "alice")]), None);
        assert_eq!(vars(&[("PAM_TYPE", "auth"), ("PAM_USER", "")]), None);
    }
}
