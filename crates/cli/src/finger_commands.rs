//! `pam-biometrics finger`: fingerprint commands over fprintd.
//!
//! The output and the exit codes follow fprintd-enroll, fprintd-verify,
//! fprintd-delete, and fprintd-list. fprintd and its polkit rules decide
//! which caller can use which operation for which user.

use std::io::Write;

use clap::Subcommand;
use serde::Serialize;

use crate::fprintd::{ANY_FINGER, Device, FINGER_NAMES, Fprintd, NO_ENROLLED_PRINTS, Signal};

/// The finger that `enroll` uses without `--finger`, as in fprintd-enroll.
pub const DEFAULT_ENROLL_FINGER: &str = "right-index-finger";

/// A fingerprint command.
#[derive(Debug, Subcommand)]
pub enum FingerCommand {
    /// Enroll a finger of USER. The default is the current user.
    Enroll {
        /// The user.
        user: Option<String>,
        /// The finger, for example left-index-finger.
        #[arg(long, short = 'f', default_value = DEFAULT_ENROLL_FINGER)]
        finger: String,
    },
    /// Verify a finger of USER. Exit 0 only on a match.
    Verify {
        /// The user. The default is the current user.
        user: Option<String>,
        /// The finger, or "any" for every enrolled finger.
        #[arg(long, short = 'f', default_value = ANY_FINGER)]
        finger: String,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Delete the enrolled fingers of the users.
    Delete {
        /// The users.
        #[arg(required = true)]
        users: Vec<String>,
        /// Delete only this finger.
        #[arg(long, short = 'f')]
        finger: Option<String>,
    },
    /// List the enrolled fingers of the users.
    List {
        /// The users.
        #[arg(required = true)]
        users: Vec<String>,
    },
}

/// Runs a finger command. Returns the exit code.
pub fn run<F: Fprintd>(
    command: &FingerCommand,
    fprintd: &F,
    current_user: &str,
    out: &mut dyn Write,
) -> u8 {
    let user = |user: &Option<String>| user.clone().unwrap_or_else(|| current_user.to_owned());
    match command {
        FingerCommand::Enroll { user: name, finger } => enroll(fprintd, &user(name), finger, out),
        FingerCommand::Verify {
            user: name,
            finger,
            json,
        } => verify(fprintd, &user(name), finger, *json, out),
        FingerCommand::Delete { users, finger } => delete(fprintd, users, finger.as_deref(), out),
        FingerCommand::List { users } => list(fprintd, users, out),
    }
}

/// Checks a finger name. `any` is valid only if `allow_any` is set.
fn check_finger(finger: &str, allow_any: bool, out: &mut dyn Write) -> bool {
    if FINGER_NAMES.contains(&finger) || (allow_any && finger == ANY_FINGER) {
        return true;
    }
    let mut names: Vec<&str> = Vec::new();
    if allow_any {
        names.push(ANY_FINGER);
    }
    names.extend(FINGER_NAMES);
    let _ = writeln!(
        out,
        "Invalid finger name '{finger}'. Name must be one of {}",
        names.join(", ")
    );
    false
}

fn enroll<F: Fprintd>(fprintd: &F, user: &str, finger: &str, out: &mut dyn Write) -> u8 {
    if !check_finger(finger, false, out) {
        return 1;
    }
    let path = match fprintd.default_device() {
        Ok(path) => path,
        Err(error) => {
            let _ = writeln!(out, "Impossible to enroll: {}", error.message);
            return 1;
        }
    };
    let _ = writeln!(out, "Using device {path}");
    let mut device = match fprintd.device(&path) {
        Ok(device) => device,
        Err(error) => {
            let _ = writeln!(out, "failed to connect to device: {}", error.message);
            return 1;
        }
    };
    if let Err(error) = device.claim(user) {
        let _ = writeln!(out, "failed to claim device: {}", error.message);
        return 1;
    }

    let _ = writeln!(out, "Enrolling {finger} finger.");
    let mut completed = false;
    let mut failed = false;
    if let Err(error) = device.enroll_start(finger) {
        let _ = writeln!(out, "EnrollStart failed: {}", error.message);
        failed = true;
    } else {
        while let Some(signal) = device.next_signal() {
            if let Signal::EnrollStatus { result, done } = signal {
                let _ = writeln!(out, "Enroll result: {result}");
                if done {
                    completed = result == "enroll-completed";
                    break;
                }
            }
        }
        if let Err(error) = device.enroll_stop() {
            let _ = writeln!(out, "EnrollStop failed: {}", error.message);
            failed = true;
        }
    }
    if let Err(error) = device.release() {
        let _ = writeln!(out, "ReleaseDevice failed: {}", error.message);
        failed = true;
    }
    u8::from(failed || !completed)
}

/// The state that `verify --json` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerifyState {
    /// fprintd reported `verify-match`.
    Match,
    /// fprintd reported `verify-no-match`.
    NoMatch,
    /// No device, no enrolled finger, an error, or another result.
    Unavailable,
}

impl VerifyState {
    /// Maps the last `VerifyStatus` result to a state.
    #[must_use]
    pub fn from_result(result: Option<&str>) -> Self {
        match result {
            Some("verify-match") => Self::Match,
            Some("verify-no-match") => Self::NoMatch,
            _ => Self::Unavailable,
        }
    }
}

#[derive(Debug, Serialize)]
struct VerifyReport<'a> {
    state: VerifyState,
    finger: Option<&'a str>,
    device: Option<&'a str>,
}

/// Writes the fprintd-verify lines unless the output is JSON.
struct Lines<'a> {
    out: &'a mut dyn Write,
    quiet: bool,
}

impl Lines<'_> {
    fn say(&mut self, line: &str) {
        if !self.quiet {
            let _ = writeln!(self.out, "{line}");
        }
    }
}

fn verify<F: Fprintd>(
    fprintd: &F,
    user: &str,
    finger: &str,
    json: bool,
    out: &mut dyn Write,
) -> u8 {
    if !check_finger(finger, true, out) {
        return 1;
    }
    let mut lines = Lines { out, quiet: json };
    let mut path = None;
    let mut selected = None;
    let mut last = None;
    let mut failed = false;

    match fprintd.default_device() {
        Err(error) => lines.say(&format!("Impossible to verify: {}", error.message)),
        Ok(device_path) => {
            lines.say(&format!("Using device {device_path}"));
            match fprintd.device(&device_path) {
                Err(error) => {
                    lines.say(&format!("failed to connect to device: {}", error.message));
                }
                Ok(mut device) => {
                    if let Err(error) = device.claim(user) {
                        lines.say(&format!("failed to claim device: {}", error.message));
                    } else {
                        let outcome =
                            verify_claimed(&mut device, user, finger, &mut lines, &mut selected);
                        last = outcome.0;
                        failed = outcome.1;
                        if let Err(error) = device.release() {
                            lines.say(&format!("ReleaseDevice failed: {}", error.message));
                            failed = true;
                        }
                    }
                }
            }
            path = Some(device_path);
        }
    }

    let state = VerifyState::from_result(last.as_deref());
    if json {
        let report = VerifyReport {
            state,
            finger: Some(selected.as_deref().unwrap_or(finger)),
            device: path.as_deref(),
        };
        let _ = writeln!(
            lines.out,
            "{}",
            serde_json::to_string(&report).unwrap_or_default()
        );
    }
    u8::from(failed || state != VerifyState::Match)
}

/// Verifies on a claimed device. Returns the last result and true if a
/// call failed.
fn verify_claimed<D: Device>(
    device: &mut D,
    user: &str,
    finger: &str,
    lines: &mut Lines<'_>,
    selected: &mut Option<String>,
) -> (Option<String>, bool) {
    let fingers = match device.list_enrolled_fingers(user) {
        Ok(fingers) => fingers,
        Err(error) if error.is(NO_ENROLLED_PRINTS) => Vec::new(),
        Err(error) => {
            lines.say(&format!("ListEnrolledFingers failed: {}", error.message));
            return (None, true);
        }
    };
    if fingers.is_empty() {
        lines.say("No fingers enrolled for this device.");
        return (None, true);
    }
    lines.say("Listing enrolled fingers:");
    for (index, name) in fingers.iter().enumerate() {
        lines.say(&format!(" - #{index}: {name}"));
    }
    if finger != ANY_FINGER && !fingers.iter().any(|name| name == finger) {
        lines.say(&format!("Finger '{finger}' not enrolled for user {user}."));
        return (None, true);
    }

    if let Err(error) = device.verify_start(finger) {
        lines.say(&format!("VerifyStart failed: {}", error.message));
        return (None, true);
    }
    lines.say("Verify started!");
    let mut last = None;
    while let Some(signal) = device.next_signal() {
        match signal {
            Signal::VerifyFingerSelected(name) => {
                lines.say(&format!("Verifying: {name}"));
                *selected = Some(name);
            }
            Signal::VerifyStatus { result, done } => {
                let state = if done { "done" } else { "not done" };
                lines.say(&format!("Verify result: {result} ({state})"));
                last = Some(result);
                if done {
                    break;
                }
            }
            Signal::EnrollStatus { .. } => {}
        }
    }
    if let Err(error) = device.verify_stop() {
        lines.say(&format!("VerifyStop failed: {}", error.message));
        return (last, true);
    }
    (last, false)
}

/// Prints the devices like fprintd-delete and fprintd-list. Returns `None`
/// if there is no device.
fn devices<F: Fprintd>(fprintd: &F, out: &mut dyn Write) -> Option<Vec<String>> {
    let devices = match fprintd.devices() {
        Ok(devices) => devices,
        Err(error) => {
            let _ = writeln!(out, "Impossible to get devices: {}", error.message);
            return None;
        }
    };
    if devices.is_empty() {
        let _ = writeln!(out, "No devices available");
        return None;
    }
    let _ = writeln!(out, "found {} devices", devices.len());
    for path in &devices {
        let _ = writeln!(out, "Device at {path}");
    }
    Some(devices)
}

fn delete<F: Fprintd>(
    fprintd: &F,
    users: &[String],
    finger: Option<&str>,
    out: &mut dyn Write,
) -> u8 {
    if let Some(finger) = finger
        && !check_finger(finger, false, out)
    {
        return 1;
    }
    let Some(paths) = devices(fprintd, out) else {
        return 1;
    };
    let mut status = 0;
    for path in &paths {
        let _ = writeln!(out, "Using device {path}");
        let device = match fprintd.device(path) {
            Ok(device) => device,
            Err(error) => {
                let _ = writeln!(out, "failed to connect to device: {}", error.message);
                status = 1;
                continue;
            }
        };
        let name = device.name().unwrap_or_else(|_| path.clone());
        for user in users {
            if let Err(error) = device.claim(user) {
                let _ = writeln!(out, "failed to claim device: {}", error.message);
                status = 1;
                continue;
            }
            let deleted = match finger {
                Some(finger) => device.delete_enrolled_finger(finger),
                None => device.delete_enrolled_fingers(),
            };
            match (deleted, finger) {
                (Ok(()), Some(finger)) => {
                    let _ = writeln!(out, "Fingerprint {finger} of user {user} deleted on {name}");
                }
                (Ok(()), None) => {
                    let _ = writeln!(out, "Fingerprints of user {user} deleted on {name}");
                }
                (Err(error), _) if error.is(NO_ENROLLED_PRINTS) => {
                    let _ = writeln!(out, "No fingerprints to delete on {name}");
                }
                (Err(error), _) => {
                    let _ = writeln!(out, "Failed to delete fingerprints: {}", error.message);
                    status = 1;
                }
            }
            if let Err(error) = device.release() {
                let _ = writeln!(out, "ReleaseDevice failed: {}", error.message);
                status = 1;
            }
        }
    }
    status
}

fn list<F: Fprintd>(fprintd: &F, users: &[String], out: &mut dyn Write) -> u8 {
    let Some(paths) = devices(fprintd, out) else {
        return 1;
    };
    let mut status = 0;
    for path in &paths {
        let _ = writeln!(out, "Using device {path}");
        let device = match fprintd.device(path) {
            Ok(device) => device,
            Err(error) => {
                let _ = writeln!(out, "failed to connect to device: {}", error.message);
                status = 1;
                continue;
            }
        };
        let name = device.name().unwrap_or_else(|_| path.clone());
        for user in users {
            let fingers = match device.list_enrolled_fingers(user) {
                Ok(fingers) => fingers,
                Err(error) if error.is(NO_ENROLLED_PRINTS) => Vec::new(),
                Err(error) => {
                    let _ = writeln!(out, "ListEnrolledFingers failed: {}", error.message);
                    status = 1;
                    continue;
                }
            };
            if fingers.is_empty() {
                let _ = writeln!(out, "User {user} has no fingers enrolled for {name}.");
                continue;
            }
            let scan_type = device.scan_type().unwrap_or_default();
            let _ = writeln!(out, "Fingerprints for user {user} on {name} ({scan_type}):");
            for (index, finger) in fingers.iter().enumerate() {
                let _ = writeln!(out, " - #{index}: {finger}");
            }
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use super::*;
    use crate::fprintd::Error;

    const PATH: &str = "/net/reactivated/Fprint/Device/0";
    const NAME: &str = "Goodix MOC Fingerprint Sensor";

    fn error(name: &str, message: &str) -> Error {
        Error {
            name: Some(name.to_owned()),
            message: message.to_owned(),
        }
    }

    fn no_prints() -> Error {
        error(NO_ENROLLED_PRINTS, "No fingerprints enrolled")
    }

    /// Scripted fprintd. Each device call appends a line to `calls`.
    #[derive(Clone)]
    struct Mock {
        devices: Vec<String>,
        fail_devices: Option<Error>,
        fail_claim: Option<Error>,
        fail_delete: Option<Error>,
        fail_verify_start: Option<Error>,
        fingers: Result<Vec<String>, Error>,
        signals: VecDeque<Signal>,
        calls: Rc<RefCell<Vec<String>>>,
    }

    impl Mock {
        fn new() -> Self {
            Self {
                devices: vec![PATH.to_owned()],
                fail_devices: None,
                fail_claim: None,
                fail_delete: None,
                fail_verify_start: None,
                fingers: Ok(vec![
                    "right-index-finger".to_owned(),
                    "left-thumb".to_owned(),
                ]),
                signals: VecDeque::new(),
                calls: Rc::default(),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn record(&self, call: String) {
            self.calls.borrow_mut().push(call);
        }
    }

    impl Fprintd for Mock {
        type Device = Self;

        fn devices(&self) -> Result<Vec<String>, Error> {
            match &self.fail_devices {
                Some(error) => Err(error.clone()),
                None => Ok(self.devices.clone()),
            }
        }

        fn default_device(&self) -> Result<String, Error> {
            match (&self.fail_devices, self.devices.first()) {
                (Some(error), _) => Err(error.clone()),
                (None, Some(path)) => Ok(path.clone()),
                (None, None) => Err(error(
                    "net.reactivated.Fprint.Error.NoSuchDevice",
                    "No devices available",
                )),
            }
        }

        fn device(&self, _path: &str) -> Result<Self, Error> {
            Ok(self.clone())
        }
    }

    impl Device for Mock {
        fn name(&self) -> Result<String, Error> {
            Ok(NAME.to_owned())
        }

        fn scan_type(&self) -> Result<String, Error> {
            Ok("press".to_owned())
        }

        fn claim(&self, user: &str) -> Result<(), Error> {
            self.record(format!("Claim {user}"));
            self.fail_claim.clone().map_or(Ok(()), Err)
        }

        fn release(&self) -> Result<(), Error> {
            self.record("Release".to_owned());
            Ok(())
        }

        fn list_enrolled_fingers(&self, user: &str) -> Result<Vec<String>, Error> {
            self.record(format!("ListEnrolledFingers {user}"));
            self.fingers.clone()
        }

        fn delete_enrolled_fingers(&self) -> Result<(), Error> {
            self.record("DeleteEnrolledFingers2".to_owned());
            self.fail_delete.clone().map_or(Ok(()), Err)
        }

        fn delete_enrolled_finger(&self, finger: &str) -> Result<(), Error> {
            self.record(format!("DeleteEnrolledFinger {finger}"));
            self.fail_delete.clone().map_or(Ok(()), Err)
        }

        fn verify_start(&mut self, finger: &str) -> Result<(), Error> {
            self.record(format!("VerifyStart {finger}"));
            self.fail_verify_start.clone().map_or(Ok(()), Err)
        }

        fn verify_stop(&self) -> Result<(), Error> {
            self.record("VerifyStop".to_owned());
            Ok(())
        }

        fn enroll_start(&mut self, finger: &str) -> Result<(), Error> {
            self.record(format!("EnrollStart {finger}"));
            Ok(())
        }

        fn enroll_stop(&self) -> Result<(), Error> {
            self.record("EnrollStop".to_owned());
            Ok(())
        }

        fn next_signal(&mut self) -> Option<Signal> {
            self.signals.pop_front()
        }
    }

    fn run_mock(mock: &Mock, command: &FingerCommand) -> (u8, String) {
        let mut out = Vec::new();
        let code = run(command, mock, "alice", &mut out);
        (code, String::from_utf8(out).unwrap())
    }

    fn verify_status(result: &str, done: bool) -> Signal {
        Signal::VerifyStatus {
            result: result.to_owned(),
            done,
        }
    }

    fn enroll_status(result: &str, done: bool) -> Signal {
        Signal::EnrollStatus {
            result: result.to_owned(),
            done,
        }
    }

    fn enroll_command(finger: &str) -> FingerCommand {
        FingerCommand::Enroll {
            user: None,
            finger: finger.to_owned(),
        }
    }

    fn verify_command(finger: &str, json: bool) -> FingerCommand {
        FingerCommand::Verify {
            user: None,
            finger: finger.to_owned(),
            json,
        }
    }

    #[test]
    fn enroll_completes() {
        let mut mock = Mock::new();
        mock.signals = [
            enroll_status("enroll-stage-passed", false),
            enroll_status("enroll-retry-scan", false),
            enroll_status("enroll-stage-passed", false),
            enroll_status("enroll-completed", true),
        ]
        .into();
        let (code, out) = run_mock(&mock, &enroll_command(DEFAULT_ENROLL_FINGER));
        assert_eq!(code, 0);
        assert_eq!(
            out,
            format!(
                "Using device {PATH}\nEnrolling right-index-finger finger.\n\
                 Enroll result: enroll-stage-passed\nEnroll result: enroll-retry-scan\n\
                 Enroll result: enroll-stage-passed\nEnroll result: enroll-completed\n"
            )
        );
        assert_eq!(
            mock.calls(),
            [
                "Claim alice",
                "EnrollStart right-index-finger",
                "EnrollStop",
                "Release"
            ]
        );
    }

    #[test]
    fn enroll_failure_releases_the_device() {
        let mut mock = Mock::new();
        mock.signals = [enroll_status("enroll-failed", true)].into();
        let (code, out) = run_mock(&mock, &enroll_command("left-thumb"));
        assert_eq!(code, 1);
        assert!(out.ends_with("Enroll result: enroll-failed\n"), "{out}");
        assert_eq!(mock.calls().last().map(String::as_str), Some("Release"));

        // The bus connection ends before a final status.
        let mock = Mock::new();
        let (code, _) = run_mock(&mock, &enroll_command("left-thumb"));
        assert_eq!(code, 1);
        assert_eq!(mock.calls().last().map(String::as_str), Some("Release"));
    }

    #[test]
    fn enroll_rejects_invalid_fingers_before_dbus() {
        let mock = Mock::new();
        for finger in ["any", "nose"] {
            let (code, out) = run_mock(&mock, &enroll_command(finger));
            assert_eq!(code, 1);
            assert_eq!(
                out,
                format!(
                    "Invalid finger name '{finger}'. Name must be one of left-thumb, \
                     left-index-finger, left-middle-finger, left-ring-finger, \
                     left-little-finger, right-thumb, right-index-finger, \
                     right-middle-finger, right-ring-finger, right-little-finger\n"
                )
            );
        }
        assert!(mock.calls().is_empty());
    }

    #[test]
    fn enroll_without_device() {
        let mut mock = Mock::new();
        mock.devices.clear();
        let (code, out) = run_mock(&mock, &enroll_command(DEFAULT_ENROLL_FINGER));
        assert_eq!(code, 1);
        assert_eq!(out, "Impossible to enroll: No devices available\n");
        assert!(mock.calls().is_empty());
    }

    #[test]
    fn verify_any_finger_matches() {
        let mut mock = Mock::new();
        mock.signals = [
            Signal::VerifyFingerSelected("any".to_owned()),
            verify_status("verify-retry-scan", false),
            verify_status("verify-match", true),
        ]
        .into();
        let (code, out) = run_mock(&mock, &verify_command(ANY_FINGER, false));
        assert_eq!(code, 0);
        assert_eq!(
            out,
            format!(
                "Using device {PATH}\nListing enrolled fingers:\n - #0: right-index-finger\n\
                 \x20- #1: left-thumb\nVerify started!\nVerifying: any\n\
                 Verify result: verify-retry-scan (not done)\n\
                 Verify result: verify-match (done)\n"
            )
        );
        assert_eq!(
            mock.calls(),
            [
                "Claim alice",
                "ListEnrolledFingers alice",
                "VerifyStart any",
                "VerifyStop",
                "Release"
            ]
        );
    }

    #[test]
    fn verify_json() {
        let mut mock = Mock::new();
        mock.signals = [
            Signal::VerifyFingerSelected("left-thumb".to_owned()),
            verify_status("verify-match", true),
        ]
        .into();
        let (code, out) = run_mock(&mock, &verify_command("left-thumb", true));
        assert_eq!(code, 0);
        assert_eq!(
            out,
            format!("{{\"state\":\"match\",\"finger\":\"left-thumb\",\"device\":\"{PATH}\"}}\n")
        );

        let mut mock = Mock::new();
        mock.signals = [verify_status("verify-no-match", true)].into();
        let (code, out) = run_mock(&mock, &verify_command(ANY_FINGER, true));
        assert_eq!(code, 1);
        assert_eq!(
            out,
            format!("{{\"state\":\"no-match\",\"finger\":\"any\",\"device\":\"{PATH}\"}}\n")
        );

        let mut mock = Mock::new();
        mock.devices.clear();
        let (code, out) = run_mock(&mock, &verify_command(ANY_FINGER, true));
        assert_eq!(code, 1);
        assert_eq!(
            out,
            "{\"state\":\"unavailable\",\"finger\":\"any\",\"device\":null}\n"
        );
    }

    #[test]
    fn verify_no_match_fails() {
        let mut mock = Mock::new();
        mock.signals = [verify_status("verify-no-match", true)].into();
        let (code, out) = run_mock(&mock, &verify_command(ANY_FINGER, false));
        assert_eq!(code, 1);
        assert!(
            out.ends_with("Verify result: verify-no-match (done)\n"),
            "{out}"
        );
    }

    #[test]
    fn verify_without_enrolled_fingers() {
        for fingers in [Err(no_prints()), Ok(Vec::new())] {
            let mut mock = Mock::new();
            mock.fingers = fingers;
            let (code, out) = run_mock(&mock, &verify_command(ANY_FINGER, false));
            assert_eq!(code, 1);
            assert_eq!(
                out,
                format!("Using device {PATH}\nNo fingers enrolled for this device.\n")
            );
            assert_eq!(
                mock.calls(),
                ["Claim alice", "ListEnrolledFingers alice", "Release"]
            );

            let (code, out) = run_mock(&mock, &verify_command(ANY_FINGER, true));
            assert_eq!(code, 1);
            assert_eq!(
                out,
                format!("{{\"state\":\"unavailable\",\"finger\":\"any\",\"device\":\"{PATH}\"}}\n")
            );
        }
    }

    #[test]
    fn verify_finger_not_enrolled() {
        let mock = Mock::new();
        let (code, out) = run_mock(
            &mock,
            &FingerCommand::Verify {
                user: Some("bob".to_owned()),
                finger: "right-thumb".to_owned(),
                json: false,
            },
        );
        assert_eq!(code, 1);
        assert!(
            out.ends_with("Finger 'right-thumb' not enrolled for user bob.\n"),
            "{out}"
        );
        assert_eq!(mock.calls().last().map(String::as_str), Some("Release"));
    }

    #[test]
    fn verify_claim_failure() {
        let mut mock = Mock::new();
        mock.fail_claim = Some(error(
            "net.reactivated.Fprint.Error.PermissionDenied",
            "Not Authorized: net.reactivated.fprint.device.setusername",
        ));
        let (code, out) = run_mock(&mock, &verify_command(ANY_FINGER, false));
        assert_eq!(code, 1);
        assert!(
            out.ends_with(
                "failed to claim device: Not Authorized: net.reactivated.fprint.device.setusername\n"
            ),
            "{out}"
        );
        // The claim failed, so there is nothing to release.
        assert_eq!(mock.calls(), ["Claim alice"]);
    }

    #[test]
    fn verify_start_failure_releases_the_device() {
        let mut mock = Mock::new();
        mock.fail_verify_start = Some(error(
            "net.reactivated.Fprint.Error.Internal",
            "Device busy",
        ));
        let (code, out) = run_mock(&mock, &verify_command(ANY_FINGER, false));
        assert_eq!(code, 1);
        assert!(out.ends_with("VerifyStart failed: Device busy\n"), "{out}");
        assert_eq!(mock.calls().last().map(String::as_str), Some("Release"));
    }

    #[test]
    fn verify_states() {
        assert_eq!(
            VerifyState::from_result(Some("verify-match")),
            VerifyState::Match
        );
        assert_eq!(
            VerifyState::from_result(Some("verify-no-match")),
            VerifyState::NoMatch
        );
        for result in [
            Some("verify-disconnected"),
            Some("verify-unknown-error"),
            Some("verify-retry-scan"),
            None,
        ] {
            assert_eq!(VerifyState::from_result(result), VerifyState::Unavailable);
        }
    }

    #[test]
    fn delete_all_fingers() {
        let mock = Mock::new();
        let (code, out) = run_mock(
            &mock,
            &FingerCommand::Delete {
                users: vec!["alice".to_owned(), "bob".to_owned()],
                finger: None,
            },
        );
        assert_eq!(code, 0);
        assert_eq!(
            out,
            format!(
                "found 1 devices\nDevice at {PATH}\nUsing device {PATH}\n\
                 Fingerprints of user alice deleted on {NAME}\n\
                 Fingerprints of user bob deleted on {NAME}\n"
            )
        );
        assert_eq!(
            mock.calls(),
            [
                "Claim alice",
                "DeleteEnrolledFingers2",
                "Release",
                "Claim bob",
                "DeleteEnrolledFingers2",
                "Release"
            ]
        );
    }

    #[test]
    fn delete_one_finger() {
        let mock = Mock::new();
        let (code, out) = run_mock(
            &mock,
            &FingerCommand::Delete {
                users: vec!["alice".to_owned()],
                finger: Some("left-thumb".to_owned()),
            },
        );
        assert_eq!(code, 0);
        assert!(
            out.ends_with(&format!(
                "Fingerprint left-thumb of user alice deleted on {NAME}\n"
            )),
            "{out}"
        );
        assert_eq!(
            mock.calls(),
            ["Claim alice", "DeleteEnrolledFinger left-thumb", "Release"]
        );
    }

    #[test]
    fn delete_errors() {
        let mut mock = Mock::new();
        mock.fail_delete = Some(no_prints());
        let users = vec!["alice".to_owned()];
        let command = FingerCommand::Delete {
            users: users.clone(),
            finger: None,
        };
        let (code, out) = run_mock(&mock, &command);
        assert_eq!(code, 0);
        assert!(
            out.ends_with(&format!("No fingerprints to delete on {NAME}\n")),
            "{out}"
        );

        let mut mock = Mock::new();
        mock.fail_delete = Some(error(
            "net.reactivated.Fprint.Error.PermissionDenied",
            "Not Authorized",
        ));
        let (code, out) = run_mock(&mock, &command);
        assert_eq!(code, 1);
        assert!(
            out.ends_with("Failed to delete fingerprints: Not Authorized\n"),
            "{out}"
        );
        assert_eq!(mock.calls().last().map(String::as_str), Some("Release"));

        let mock = Mock::new();
        let (code, out) = run_mock(
            &mock,
            &FingerCommand::Delete {
                users,
                finger: Some("any".to_owned()),
            },
        );
        assert_eq!(code, 1);
        assert!(out.starts_with("Invalid finger name 'any'."), "{out}");
    }

    #[test]
    fn list_fingers() {
        let mut mock = Mock::new();
        let command = FingerCommand::List {
            users: vec!["alice".to_owned()],
        };
        let (code, out) = run_mock(&mock, &command);
        assert_eq!(code, 0);
        assert_eq!(
            out,
            format!(
                "found 1 devices\nDevice at {PATH}\nUsing device {PATH}\n\
                 Fingerprints for user alice on {NAME} (press):\n\
                 \x20- #0: right-index-finger\n - #1: left-thumb\n"
            )
        );
        // list does not claim the device, as in fprintd-list.
        assert_eq!(mock.calls(), ["ListEnrolledFingers alice"]);

        mock.fingers = Err(no_prints());
        let (code, out) = run_mock(&mock, &command);
        assert_eq!(code, 0);
        assert!(
            out.ends_with(&format!("User alice has no fingers enrolled for {NAME}.\n")),
            "{out}"
        );

        mock.fingers = Err(error("org.freedesktop.DBus.Error.Failed", "boom"));
        let (code, out) = run_mock(&mock, &command);
        assert_eq!(code, 1);
        assert!(out.ends_with("ListEnrolledFingers failed: boom\n"), "{out}");
    }

    #[test]
    fn list_without_devices() {
        let mut mock = Mock::new();
        mock.devices.clear();
        let command = FingerCommand::List {
            users: vec!["alice".to_owned()],
        };
        let (code, out) = run_mock(&mock, &command);
        assert_eq!(code, 1);
        assert_eq!(out, "No devices available\n");

        mock.fail_devices = Some(error(
            "org.freedesktop.DBus.Error.ServiceUnknown",
            "The name net.reactivated.Fprint was not provided by any .service files",
        ));
        let (code, out) = run_mock(&mock, &command);
        assert_eq!(code, 1);
        assert_eq!(
            out,
            "Impossible to get devices: The name net.reactivated.Fprint was not provided by any .service files\n"
        );
    }

    #[test]
    fn dbus_errors_map_to_name_and_message() {
        let error = Error::from(zbus::Error::Failure("bus closed".to_owned()));
        assert_eq!(error.name, None);
        assert!(error.message.contains("bus closed"), "{}", error.message);
        assert!(!error.is(NO_ENROLLED_PRINTS));
        assert!(no_prints().is(NO_ENROLLED_PRINTS));
    }
}
