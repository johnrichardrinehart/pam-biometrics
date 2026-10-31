//! `pam-biometrics face`: commands for the face daemon.
//!
//! enroll, verify, delete, and list follow fprintd-enroll, fprintd-verify,
//! fprintd-delete, and fprintd-list.

use std::path::Path;
use std::time::Duration;

use clap::Subcommand;
use pam_biometrics_policy::{FaceClass, FaceSettings};
use pam_biometrics_protocol::{Op, Reply, Request, ScanResult, call};

use crate::agent::TtyAgent;
use crate::{current_user, load_policy, user_or_current};

/// A face command.
#[derive(Debug, Subcommand)]
pub enum FaceCommand {
    /// Enroll the face of USER. The default is the current user.
    Enroll {
        /// The user.
        user: Option<String>,
        /// Keep the enrolled samples and add new ones. The model keeps the newest 30.
        #[arg(long)]
        add: bool,
    },
    /// Scan now and compare with the face of USER. Exit 0 only on a match.
    Verify {
        /// The user. The default is the current user.
        user: Option<String>,
        /// Print the daemon result and its class as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Delete the enrolled faces of the users.
    Delete {
        /// The users.
        #[arg(required = true)]
        users: Vec<String>,
    },
    /// List the enrolled faces of the users.
    List {
        /// The users.
        #[arg(required = true)]
        users: Vec<String>,
    },
    /// Start a background scan for USER. The next PAM step uses the result.
    Scan {
        /// The user. The default is the current user.
        user: Option<String>,
    },
    /// Print the state of the last scan as one line for a lock screen.
    Status {
        /// The user. The default is the current user.
        user: Option<String>,
        /// Classify with the thresholds of this PAM service.
        #[arg(long)]
        service: Option<String>,
    },
    /// Wait for a running scan, then print its state like `status`.
    Wait {
        /// The user. The default is the current user.
        user: Option<String>,
        /// Classify with the thresholds of this PAM service.
        #[arg(long)]
        service: Option<String>,
    },
}

const SHORT_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(60);
const ENROLL_TIMEOUT: Duration = Duration::from_secs(120);
/// The extra time for a polkit authentication, for example a password.
const AUTH_TIMEOUT: Duration = Duration::from_secs(180);

/// The daemon error when polkit refuses a request.
const NOT_AUTHORIZED: &str = "not authorized";

/// Returns true if the daemon asks polkit before it handles `op` for
/// `user`. Root needs no authentication.
fn needs_authorization(op: Op, user: &str) -> bool {
    if nix::unistd::getuid().is_root() {
        return false;
    }
    match op {
        Op::Enroll | Op::Delete => true,
        Op::Verify | Op::List => current_user().map_or(true, |current| current != user),
        Op::Scan | Op::Status | Op::Wait | Op::Take => false,
    }
}

/// Sends a request. If the request needs polkit, a terminal agent asks
/// for the password while the request runs.
fn authorized_request(
    socket: &Path,
    request: &Request,
    timeout: Duration,
) -> Result<Reply, String> {
    if !needs_authorization(request.op, &request.user) {
        return self::request(socket, request, timeout);
    }
    let agent = TtyAgent::start_for_terminal();
    let reply = self::request(socket, request, timeout + AUTH_TIMEOUT);
    drop(agent);
    if let Ok(reply) = &reply
        && reply.error.as_deref() == Some(NOT_AUTHORIZED)
    {
        eprintln!(
            "pam-biometrics: polkit did not authorize this request. Run the command in a \
             terminal to authenticate, or add a polkit rule for the action."
        );
    }
    reply
}

/// Runs a face command against the daemon at `socket`. Returns the exit
/// code.
pub fn run(command: &FaceCommand, socket: &Path, policy: &Path) -> Result<u8, String> {
    match command {
        FaceCommand::Enroll { user, add } => enroll(socket, user.clone(), *add),
        FaceCommand::Verify { user, json } => verify(socket, policy, user.clone(), *json),
        FaceCommand::Delete { users } => Ok(delete_or_list(socket, Op::Delete, users)),
        FaceCommand::List { users } => Ok(delete_or_list(socket, Op::List, users)),
        FaceCommand::Scan { user } => scan(socket, user.clone()),
        FaceCommand::Status { user, service } => {
            status(socket, policy, user.clone(), service.as_deref(), false)
        }
        FaceCommand::Wait { user, service } => {
            status(socket, policy, user.clone(), service.as_deref(), true)
        }
    }
}

fn request(socket: &Path, request: &Request, timeout: Duration) -> Result<Reply, String> {
    call(socket, request, timeout).map_err(|error| {
        format!(
            "cannot reach pam-biometricsd at {}: {error}",
            socket.display()
        )
    })
}

fn device(reply: &Reply) -> &str {
    reply.device.as_deref().unwrap_or("unknown device")
}

/// Returns the line for a lock screen label.
fn status_text(result: Option<&ScanResult>, face: &FaceSettings) -> &'static str {
    match result {
        None => "",
        Some(ScanResult::Scanning) => "Face: scanning…",
        Some(ScanResult::NoModel) => "Face: not enrolled",
        Some(ScanResult::Finished { best, faces }) => match face.classify(*best, *faces) {
            FaceClass::Match => "Face: recognized",
            FaceClass::Uncertain => "Face: not sure",
            FaceClass::Reject => "Face: not recognized",
            FaceClass::Absent => "Face: no face found",
        },
    }
}

/// Returns the fprintd-verify result name of a face class.
fn verify_result(class: FaceClass) -> &'static str {
    match class {
        FaceClass::Match => "verify-match",
        FaceClass::Reject => "verify-no-match",
        FaceClass::Uncertain | FaceClass::Absent => "verify-retry-scan",
    }
}

fn enroll(socket: &Path, user: Option<String>, add: bool) -> Result<u8, String> {
    let user = user_or_current(user)?;
    println!("Enrolling face. Look at the camera.");
    let mut enroll = Request::new(Op::Enroll, &user);
    enroll.add = add;
    let reply = authorized_request(socket, &enroll, ENROLL_TIMEOUT)?;
    if let Some(error) = &reply.error {
        println!("Enroll result: enroll-failed ({error})");
        return Ok(1);
    }
    println!("Using device {}", device(&reply));
    println!(
        "Enroll result: enroll-completed ({} samples)",
        reply.samples.unwrap_or_default()
    );
    Ok(0)
}

fn verify(socket: &Path, policy: &Path, user: Option<String>, json: bool) -> Result<u8, String> {
    let user = user_or_current(user)?;
    let face = load_policy(policy)?.resolve(None, Some(&user)).face;
    let reply = authorized_request(socket, &Request::new(Op::Verify, &user), VERIFY_TIMEOUT)?;
    let class = match &reply.result {
        Some(ScanResult::Finished { best, faces }) => Some(face.classify(*best, *faces)),
        _ => None,
    };
    if json {
        let mut value = serde_json::to_value(&reply).map_err(|error| error.to_string())?;
        if let Some(class) = class {
            value["class"] = serde_json::to_value(class).map_err(|error| error.to_string())?;
        }
        println!("{value}");
    } else if let Some(error) = &reply.error {
        println!("Impossible to verify: {error}");
    } else if let Some(class) = class {
        println!("Using device {}", device(&reply));
        println!("Verifying: face");
        println!("Verify result: {} (done)", verify_result(class));
    } else {
        println!("No face enrolled for this device.");
    }
    Ok(u8::from(class != Some(FaceClass::Match)))
}

fn delete_or_list(socket: &Path, op: Op, users: &[String]) -> u8 {
    let mut status = 0;
    for user in users {
        let reply = authorized_request(socket, &Request::new(op, user), SHORT_TIMEOUT)
            .unwrap_or_else(Reply::error);
        if let Some(error) = &reply.error {
            println!("Failed for user {user}: {error}");
            status = 1;
        } else if op == Op::Delete {
            if reply.deleted == Some(true) {
                println!("Face of user {user} deleted on {}", device(&reply));
            } else {
                println!("No face to delete on {}", device(&reply));
            }
        } else if let Some(samples) = reply.samples.filter(|samples| *samples > 0) {
            println!("Face for user {user} on {}:", device(&reply));
            println!(" - #0: face ({samples} samples)");
        } else {
            println!("User {user} has no face enrolled for {}.", device(&reply));
        }
    }
    status
}

fn scan(socket: &Path, user: Option<String>) -> Result<u8, String> {
    let user = user_or_current(user)?;
    let reply = request(socket, &Request::new(Op::Scan, &user), SHORT_TIMEOUT)?;
    if let Some(error) = &reply.error {
        println!("Failed for user {user}: {error}");
        return Ok(1);
    }
    match (reply.started, &reply.result) {
        (Some(true), _) => println!("Scanning the face of {user} on {}.", device(&reply)),
        (_, Some(ScanResult::NoModel)) => {
            println!("User {user} has no face enrolled for {}.", device(&reply));
            return Ok(1);
        }
        _ => println!("A scan for {user} is already in progress."),
    }
    Ok(0)
}

/// Prints the scan state. A failure prints an empty line, so that a lock
/// screen label stays empty.
fn status(
    socket: &Path,
    policy: &Path,
    user: Option<String>,
    service: Option<&str>,
    wait: bool,
) -> Result<u8, String> {
    let user = user_or_current(user)?;
    let face = load_policy(policy)?.resolve(service, Some(&user)).face;
    let (op, timeout) = if wait {
        (Op::Wait, WAIT_TIMEOUT)
    } else {
        (Op::Status, SHORT_TIMEOUT)
    };
    let result = request(socket, &Request::new(op, &user), timeout)
        .ok()
        .and_then(|reply| reply.result);
    println!("{}", status_text(result.as_ref(), &face));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use pam_biometrics_policy::Settings;

    use super::*;

    #[test]
    fn status_lines() {
        let face = Settings::default().face;
        let finished = |best, faces| ScanResult::Finished { best, faces };
        assert_eq!(status_text(None, &face), "");
        assert_eq!(
            status_text(Some(&ScanResult::Scanning), &face),
            "Face: scanning…"
        );
        assert_eq!(
            status_text(Some(&ScanResult::NoModel), &face),
            "Face: not enrolled"
        );
        assert_eq!(
            status_text(Some(&finished(Some(0.2), 1)), &face),
            "Face: recognized"
        );
        assert_eq!(
            status_text(Some(&finished(Some(0.5), 5)), &face),
            "Face: not sure"
        );
        assert_eq!(
            status_text(Some(&finished(Some(0.9), 5)), &face),
            "Face: not recognized"
        );
        assert_eq!(
            status_text(Some(&finished(None, 0)), &face),
            "Face: no face found"
        );
    }

    #[test]
    fn verify_results() {
        assert_eq!(verify_result(FaceClass::Match), "verify-match");
        assert_eq!(verify_result(FaceClass::Reject), "verify-no-match");
        assert_eq!(verify_result(FaceClass::Uncertain), "verify-retry-scan");
        assert_eq!(verify_result(FaceClass::Absent), "verify-retry-scan");
    }
}
