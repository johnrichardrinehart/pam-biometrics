//! The PAM helper: `pam_biometrics.so` runs `pam-biometrics pam-session`.
//!
//! The helper runs for one auth call of the PAM stack: from the `start`
//! step before the password module to the `finish` step after it. The
//! enabled factors run in the background for the whole time.
//!
//! # Protocol
//!
//! The module and the helper exchange lines over the standard input and
//! output of the helper. A line is a word, then a space and a text for some
//! words. No text contains a line break. Each side ignores unknown lines.
//!
//! The helper sends these lines first:
//!
//! | Line               | Meaning                                                     |
//! |--------------------|-------------------------------------------------------------|
//! | `off`              | No factor is enabled. The helper exits.                     |
//! | `prompt TEXT`      | The first password prompt.                                  |
//! | `reprompt TEXT`    | The password prompt after a face trigger. It differs from `prompt`. |
//! | `trigger TEXT`     | The face trigger. Absent if the face factor is disabled.    |
//! | `after-password prompt` | `finish` will send `ask`. The module then does not watch the terminal. Absent with `after_password: wait`. |
//! | `ready`            | The end of the settings. The factors run.                   |
//!
//! Then the module sends commands:
//!
//! | Command          | Effect                                                                  |
//! |------------------|-------------------------------------------------------------------------|
//! | `scan`           | Ask for a face scan. The helper replies `scan started`, `scan running` (a scan runs already and counts), or `scan failed`. |
//! | `state`          | The helper replies `state VERDICT FACE`.                                |
//! | `finish`         | Wait for a decision until the timeout, then exit with the step exit code. |
//! | `answer trigger` | The reply to `ask`: the response was the face trigger.                 |
//! | `answer other`   | The reply to `ask`: any other response.                                |
//! | `stop`           | Stop the factors and exit. The end of the input does the same.          |
//!
//! The module may send `scan` during the wait of `finish`. A started scan
//! also gives `info Scanning face…` before the reply. A running scan gives
//! no second message. Before the prompt or the wait message, `finish` waits
//! for a scan that runs already; the fingerprint counts meanwhile, and the
//! first match or any reject decides.
//!
//! The helper sends these lines at any time:
//!
//! | Line                   | Meaning                                                                 |
//! |------------------------|-------------------------------------------------------------------------|
//! | `info TEXT`            | A line for the user.                                                    |
//! | `scan WORD`            | The reply to `scan`: `started`, `running`, or `failed`.                 |
//! | `state VERDICT FACE`   | VERDICT is `success`, `reject`, or `pending`. FACE is `scanning` or `idle`. |
//! | `ask TEXT`             | Only with `after_password: prompt`, once in `finish` before any wait: prompt with TEXT, then send `answer`. |
//!
//! The password never goes to the helper. The exit code gives the result of
//! the step: 0 for a match, 10 for a reject, and 20 without a decision.

use std::io::{BufRead as _, Write};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use pam_biometrics_policy::{AfterPassword, Combine, EXIT_NO_DECISION, Factor, Policy, Settings};

use crate::face::{Daemon, FaceTask};
use crate::fingerprint::FingerprintTask;
use crate::session::{Command, Event, FactorTask, Input, Session, Stop};

/// The password prompt after a trigger, unless the first prompt is the
/// same text.
const REPROMPT: &str = "Password: ";

/// The text that names the trigger in the default prompts.
fn trigger_hint(trigger: &str, capital: bool) -> String {
    match (trigger.is_empty(), capital) {
        (true, false) => "press Enter".to_owned(),
        (true, true) => "Press Enter".to_owned(),
        (false, false) => format!("type {trigger}"),
        (false, true) => format!("Type {trigger}"),
    }
}

/// Returns the first password prompt of `start`.
#[must_use]
pub fn password_prompt(settings: &Settings) -> String {
    if let Some(prompt) = &settings.password_prompt {
        return prompt.clone();
    }
    if !settings.enabled(Factor::Face) {
        return "Password: ".to_owned();
    }
    let trigger = &settings.face.trigger;
    if trigger.is_empty() {
        "Password (Enter to scan face): ".to_owned()
    } else {
        format!("Password (type {trigger} to scan face): ")
    }
}

/// Returns the password prompt after a trigger. It differs from `first`,
/// so that an application that answers a repeated prompt with the last
/// response does not start scans in a loop.
#[must_use]
pub fn reprompt(first: &str) -> String {
    if first == REPROMPT {
        "Password (face scan started): ".to_owned()
    } else {
        REPROMPT.to_owned()
    }
}

/// Returns the information line that `finish` shows when it waits.
#[must_use]
pub fn wait_message(settings: &Settings) -> String {
    if let Some(message) = &settings.wait_message {
        return message.clone();
    }
    let trigger = &settings.face.trigger;
    let seconds = settings.timeout_seconds;
    match (
        settings.enabled(Factor::Fingerprint),
        settings.enabled(Factor::Face),
        settings.combine,
    ) {
        (true, true, Combine::Any) => format!(
            "Touch the fingerprint reader or {} to scan your face ({seconds} s).",
            trigger_hint(trigger, false)
        ),
        (true, true, Combine::All) => format!(
            "Touch the fingerprint reader and {} to scan your face ({seconds} s).",
            trigger_hint(trigger, false)
        ),
        (true, false, _) => format!("Touch the fingerprint reader ({seconds} s)."),
        _ => format!(
            "{} to scan your face ({seconds} s).",
            trigger_hint(trigger, true)
        ),
    }
}

/// Returns the prompt of `finish` with `after_password: prompt`.
#[must_use]
pub fn after_password_prompt(settings: &Settings) -> String {
    if let Some(prompt) = &settings.after_password_prompt {
        return prompt.clone();
    }
    let trigger = &settings.face.trigger;
    match (
        settings.enabled(Factor::Fingerprint),
        settings.enabled(Factor::Face),
        settings.combine,
    ) {
        (true, true, Combine::Any) => format!(
            "Touch the fingerprint reader or {} to scan your face (other text skips): ",
            trigger_hint(trigger, false)
        ),
        (true, true, Combine::All) => format!(
            "Touch the fingerprint reader and {} to scan your face (other text skips): ",
            trigger_hint(trigger, false)
        ),
        (true, false, _) => "Touch the fingerprint reader, then press Enter: ".to_owned(),
        _ => format!(
            "{} to scan your face (other text skips): ",
            trigger_hint(trigger, true)
        ),
    }
}

/// Returns the lines that the helper sends before the commands.
#[must_use]
pub fn greeting(settings: &Settings) -> Vec<String> {
    if settings.factors.is_empty() {
        return vec!["off".to_owned()];
    }
    let first = password_prompt(settings);
    let mut lines = vec![
        format!("prompt {first}"),
        format!("reprompt {}", reprompt(&first)),
    ];
    if settings.enabled(Factor::Face) {
        lines.push(format!("trigger {}", settings.face.trigger));
    }
    if settings.after_password == AfterPassword::Prompt {
        lines.push("after-password prompt".to_owned());
    }
    lines.push("ready".to_owned());
    lines
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

/// Reads the commands of the module from the standard input.
fn read_commands(inputs: Sender<Input>) {
    thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else {
                break;
            };
            if let Some(command) = Command::parse(&line)
                && inputs.send(Input::Command(command)).is_err()
            {
                return;
            }
        }
        let _ = inputs.send(Input::Closed);
    });
}

/// Passes the factor events to the session.
fn forward(events: Receiver<Event>, inputs: Sender<Input>) {
    thread::spawn(move || {
        for event in events {
            if inputs.send(Input::Event(event)).is_err() {
                return;
            }
        }
    });
}

/// Runs the helper session for the PAM environment of the process.
pub fn run(policy_path: &Path, socket: &Path) -> i32 {
    let mut out = std::io::stdout().lock();
    let off = |out: &mut dyn Write| {
        let _ = writeln!(out, "off");
        let _ = out.flush();
        EXIT_NO_DECISION
    };
    let Some(env) = PamEnv::from_vars(|name| std::env::var(name).ok()) else {
        return off(&mut out);
    };
    let policy = match Policy::load(policy_path) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("pam-biometrics: {error}");
            return off(&mut out);
        }
    };
    let settings = policy.resolve(env.service.as_deref(), Some(&env.user));
    for line in greeting(&settings) {
        let _ = writeln!(out, "{line}");
    }
    let _ = out.flush();
    if settings.factors.is_empty() {
        return EXIT_NO_DECISION;
    }

    let daemon = || Daemon {
        socket: socket.to_owned(),
        user: env.user.clone(),
    };
    let (input_sender, inputs) = mpsc::channel();
    read_commands(input_sender.clone());
    let (event_sender, events) = mpsc::channel();
    forward(events, input_sender);
    let stops: Vec<Box<dyn Stop>> = settings
        .factors
        .iter()
        .map(|factor| -> Box<dyn FactorTask> {
            match factor {
                Factor::Fingerprint => Box::new(FingerprintTask {
                    user: env.user.clone(),
                    max_tries: settings.fingerprint.max_tries,
                }),
                Factor::Face => Box::new(FaceTask {
                    source: daemon(),
                    face: settings.face.clone(),
                }),
            }
        })
        .map(|task| task.start(event_sender.clone()))
        .collect();
    drop(event_sender);

    let ask = (settings.after_password == AfterPassword::Prompt)
        .then(|| after_password_prompt(&settings));
    let code = Session::new(
        &settings,
        wait_message(&settings),
        ask,
        inputs,
        daemon(),
        out,
    )
    .run();
    for stop in stops {
        stop.stop();
    }
    code
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn settings(factors: &[Factor]) -> Settings {
        Settings {
            factors: factors.to_vec(),
            ..Settings::default()
        }
    }

    const BOTH: &[Factor] = &[Factor::Fingerprint, Factor::Face];

    #[test]
    fn default_password_prompts() {
        let mut both = settings(BOTH);
        assert_eq!(password_prompt(&both), "Password (Enter to scan face): ");
        both.face.trigger = "f".to_owned();
        assert_eq!(password_prompt(&both), "Password (type f to scan face): ");
        // Without the face factor, the trigger means nothing.
        let mut finger = settings(&[Factor::Fingerprint]);
        finger.face.trigger = "f".to_owned();
        assert_eq!(password_prompt(&finger), "Password: ");
        assert_eq!(
            password_prompt(&settings(&[Factor::Face])),
            "Password (Enter to scan face): "
        );
    }

    #[test]
    fn policy_prompts_replace_the_defaults() {
        let mut custom = settings(BOTH);
        custom.password_prompt = Some("Passphrase: ".to_owned());
        custom.wait_message = Some("Press Super+Alt+F.".to_owned());
        assert_eq!(password_prompt(&custom), "Passphrase: ");
        assert_eq!(wait_message(&custom), "Press Super+Alt+F.");
    }

    #[test]
    fn reprompt_differs_from_the_first_prompt() {
        for first in [
            "Password (Enter to scan face): ",
            "Password: ",
            "Passphrase: ",
        ] {
            assert_ne!(reprompt(first), first, "{first}");
        }
        assert_eq!(reprompt("Password (Enter to scan face): "), "Password: ");
    }

    #[test]
    fn default_wait_messages() {
        let mut both = settings(BOTH);
        assert_eq!(
            wait_message(&both),
            "Touch the fingerprint reader or press Enter to scan your face (15 s)."
        );
        both.face.trigger = "face".to_owned();
        both.timeout_seconds = 3;
        assert_eq!(
            wait_message(&both),
            "Touch the fingerprint reader or type face to scan your face (3 s)."
        );
        both.combine = Combine::All;
        assert_eq!(
            wait_message(&both),
            "Touch the fingerprint reader and type face to scan your face (3 s)."
        );
        assert_eq!(
            wait_message(&settings(&[Factor::Fingerprint])),
            "Touch the fingerprint reader (15 s)."
        );
        let mut face = settings(&[Factor::Face]);
        assert_eq!(wait_message(&face), "Press Enter to scan your face (15 s).");
        face.face.trigger = "f".to_owned();
        assert_eq!(wait_message(&face), "Type f to scan your face (15 s).");
    }

    #[test]
    fn greetings() {
        assert_eq!(greeting(&settings(&[])), ["off"]);
        assert_eq!(
            greeting(&settings(BOTH)),
            [
                "prompt Password (Enter to scan face): ",
                "reprompt Password: ",
                "trigger ",
                "ready"
            ]
        );
        let mut custom = settings(BOTH);
        custom.face.trigger = "f".to_owned();
        custom.password_prompt = Some("Password: ".to_owned());
        assert_eq!(
            greeting(&custom),
            [
                "prompt Password: ",
                "reprompt Password (face scan started): ",
                "trigger f",
                "ready"
            ]
        );
        assert_eq!(
            greeting(&settings(&[Factor::Fingerprint])),
            [
                "prompt Password: ",
                "reprompt Password (face scan started): ",
                "ready"
            ]
        );
        let mut prompt = settings(BOTH);
        prompt.after_password = AfterPassword::Prompt;
        assert_eq!(
            greeting(&prompt),
            [
                "prompt Password (Enter to scan face): ",
                "reprompt Password: ",
                "trigger ",
                "after-password prompt",
                "ready"
            ]
        );
    }

    #[test]
    fn default_after_password_prompts() {
        let mut both = settings(BOTH);
        assert_eq!(
            after_password_prompt(&both),
            "Touch the fingerprint reader or press Enter to scan your face (other text skips): "
        );
        both.face.trigger = "f".to_owned();
        assert_eq!(
            after_password_prompt(&both),
            "Touch the fingerprint reader or type f to scan your face (other text skips): "
        );
        both.combine = Combine::All;
        assert_eq!(
            after_password_prompt(&both),
            "Touch the fingerprint reader and type f to scan your face (other text skips): "
        );
        assert_eq!(
            after_password_prompt(&settings(&[Factor::Fingerprint])),
            "Touch the fingerprint reader, then press Enter: "
        );
        let mut face = settings(&[Factor::Face]);
        assert_eq!(
            after_password_prompt(&face),
            "Press Enter to scan your face (other text skips): "
        );
        face.face.trigger = "f".to_owned();
        assert_eq!(
            after_password_prompt(&face),
            "Type f to scan your face (other text skips): "
        );
        face.after_password_prompt = Some("Press Enter for the camera: ".to_owned());
        assert_eq!(after_password_prompt(&face), "Press Enter for the camera: ");
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
