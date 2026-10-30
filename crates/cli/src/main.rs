//! pam-biometrics: the command line client and the PAM helper.
//!
//! The face commands follow fprintd-enroll, fprintd-verify, fprintd-delete,
//! and fprintd-list. This program does not link dlib. The daemon does the
//! face work.

mod face;
mod fingerprint;
mod helper;
mod step;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use pam_biometrics_policy::{DEFAULT_POLICY_PATH, FaceClass, FaceSettings, Policy};
use pam_biometrics_protocol::{DEFAULT_SOCKET, Op, Reply, Request, ScanResult, call};

/// Fingerprint and face factors for PAM.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Socket of pam-biometricsd.
    #[arg(long, global = true, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    /// Policy file.
    #[arg(long, global = true, default_value = DEFAULT_POLICY_PATH)]
    policy: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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
    /// Check or show the policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Decide the biometric factors for pam_biometrics.so.
    ///
    /// Reads PAM_USER, PAM_SERVICE, and PAM_TYPE from the environment. Exits
    /// 0 on a match, 10 on a reject, and 20 without a decision.
    PamHelper {
        /// Text to show when the step starts. It replaces the policy prompt.
        #[arg(long)]
        prompt: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Validate a policy file. A missing file is an error.
    Check {
        /// The policy file. The default is the --policy value.
        file: Option<PathBuf>,
    },
    /// Print the resolved settings for a service and a user as JSON.
    Show {
        /// The PAM service.
        #[arg(long)]
        service: Option<String>,
        /// The user.
        #[arg(long)]
        user: Option<String>,
        /// The policy file. The default is the --policy value.
        file: Option<PathBuf>,
    },
}

const SHORT_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(60);
const ENROLL_TIMEOUT: Duration = Duration::from_secs(120);

fn current_user() -> Result<String, String> {
    match nix::unistd::User::from_uid(nix::unistd::getuid()) {
        Ok(Some(user)) => Ok(user.name),
        _ => Err("cannot find the name of the current user".to_owned()),
    }
}

fn user_or_current(user: Option<String>) -> Result<String, String> {
    user.map_or_else(current_user, Ok)
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

fn load_policy(path: &Path) -> Result<Policy, String> {
    Policy::load(path).map_err(|error| error.to_string())
}

fn enroll(cli: &Cli, user: Option<String>, add: bool) -> Result<u8, String> {
    let user = user_or_current(user)?;
    println!("Enrolling face. Look at the camera.");
    let mut enroll = Request::new(Op::Enroll, &user);
    enroll.add = add;
    let reply = request(&cli.socket, &enroll, ENROLL_TIMEOUT)?;
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

fn verify(cli: &Cli, user: Option<String>, json: bool) -> Result<u8, String> {
    let user = user_or_current(user)?;
    let face = load_policy(&cli.policy)?.resolve(None, Some(&user)).face;
    let reply = request(
        &cli.socket,
        &Request::new(Op::Verify, &user),
        VERIFY_TIMEOUT,
    )?;
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

fn delete_or_list(cli: &Cli, op: Op, users: &[String]) -> u8 {
    let mut status = 0;
    for user in users {
        let reply = request(&cli.socket, &Request::new(op, user), SHORT_TIMEOUT)
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

fn scan(cli: &Cli, user: Option<String>) -> Result<u8, String> {
    let user = user_or_current(user)?;
    let reply = request(&cli.socket, &Request::new(Op::Scan, &user), SHORT_TIMEOUT)?;
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
    cli: &Cli,
    user: Option<String>,
    service: Option<&str>,
    wait: bool,
) -> Result<u8, String> {
    let user = user_or_current(user)?;
    let face = load_policy(&cli.policy)?.resolve(service, Some(&user)).face;
    let (op, timeout) = if wait {
        (Op::Wait, WAIT_TIMEOUT)
    } else {
        (Op::Status, SHORT_TIMEOUT)
    };
    let result = request(&cli.socket, &Request::new(op, &user), timeout)
        .ok()
        .and_then(|reply| reply.result);
    println!("{}", status_text(result.as_ref(), &face));
    Ok(0)
}

fn policy(cli: &Cli, command: &PolicyCommand) -> Result<u8, String> {
    match command {
        PolicyCommand::Check { file } => {
            let path = file.as_deref().unwrap_or(&cli.policy);
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            Policy::parse(&text, &path.display().to_string()).map_err(|error| error.to_string())?;
            println!("{}: valid", path.display());
            Ok(0)
        }
        PolicyCommand::Show {
            service,
            user,
            file,
        } => {
            let path = file.as_deref().unwrap_or(&cli.policy);
            let settings = load_policy(path)?.resolve(service.as_deref(), user.as_deref());
            let text =
                serde_json::to_string_pretty(&settings).map_err(|error| error.to_string())?;
            println!("{text}");
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::PamHelper { prompt } => {
            let code = helper::run(&cli.policy, &cli.socket, prompt.as_deref());
            return ExitCode::from(u8::try_from(code).unwrap_or(1));
        }
        Command::Enroll { user, add } => enroll(&cli, user.clone(), *add),
        Command::Verify { user, json } => verify(&cli, user.clone(), *json),
        Command::Delete { users } => Ok(delete_or_list(&cli, Op::Delete, users)),
        Command::List { users } => Ok(delete_or_list(&cli, Op::List, users)),
        Command::Scan { user } => scan(&cli, user.clone()),
        Command::Status { user, service } => status(&cli, user.clone(), service.as_deref(), false),
        Command::Wait { user, service } => status(&cli, user.clone(), service.as_deref(), true),
        Command::Policy { command } => policy(&cli, command),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("pam-biometrics: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;
    use pam_biometrics_policy::Settings;

    use super::*;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

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
