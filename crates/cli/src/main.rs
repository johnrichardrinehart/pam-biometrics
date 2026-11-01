//! pam-biometrics: the command line client and the PAM helper.
//!
//! The commands group by factor. This program does not link dlib. The
//! daemon does the face work.

mod agent;
mod face;
mod face_commands;
mod finger_commands;
mod fingerprint;
mod fprintd;
mod helper;
mod session;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pam_biometrics_policy::{DEFAULT_POLICY_PATH, Policy};
use pam_biometrics_protocol::DEFAULT_SOCKET;

use crate::agent::TtyAgent;
use crate::face_commands::FaceCommand;
use crate::finger_commands::FingerCommand;
use crate::fprintd::SystemFprintd;

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
    /// Enroll, verify, and scan faces through pam-biometricsd.
    Face {
        #[command(subcommand)]
        command: FaceCommand,
    },
    /// Enroll, verify, delete, and list fingers through fprintd.
    Finger {
        #[command(subcommand)]
        command: FingerCommand,
    },
    /// Check or show the policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Run the biometric factors for pam_biometrics.so from start to finish.
    ///
    /// Reads PAM_USER, PAM_SERVICE, and PAM_TYPE from the environment, and
    /// the commands of the PAM module from stdin. Exits 0 on a match, 10 on
    /// a reject, and 20 without a decision.
    PamSession,
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

/// Returns the name of the user that runs this program.
pub(crate) fn current_user() -> Result<String, String> {
    match nix::unistd::User::from_uid(nix::unistd::getuid()) {
        Ok(Some(user)) => Ok(user.name),
        _ => Err("cannot find the name of the current user".to_owned()),
    }
}

/// Returns `user`, or the name of the current user.
pub(crate) fn user_or_current(user: Option<String>) -> Result<String, String> {
    user.map_or_else(current_user, Ok)
}

/// Loads the policy file. A missing file gives the built-in defaults.
pub(crate) fn load_policy(path: &Path) -> Result<Policy, String> {
    Policy::load(path).map_err(|error| error.to_string())
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

/// Runs a finger command against fprintd on the system bus.
fn finger(command: &FingerCommand) -> Result<u8, String> {
    let user = current_user()?;
    let fprintd = match SystemFprintd::connect() {
        Ok(fprintd) => fprintd,
        Err(error) => {
            println!("Failed to connect to the system bus: {}", error.message);
            return Ok(1);
        }
    };
    // fprintd asks polkit before an enrollment or a deletion.
    let changes = matches!(
        command,
        FingerCommand::Enroll { .. } | FingerCommand::Delete { .. }
    );
    let _agent = (changes && !nix::unistd::getuid().is_root())
        .then(TtyAgent::start_for_terminal)
        .flatten();
    Ok(finger_commands::run(
        command,
        &fprintd,
        &user,
        &mut std::io::stdout().lock(),
    ))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::PamSession => {
            let code = helper::run(&cli.policy, &cli.socket);
            return ExitCode::from(u8::try_from(code).unwrap_or(1));
        }
        Command::Face { command } => face_commands::run(command, &cli.socket, &cli.policy),
        Command::Finger { command } => finger(command),
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

    use super::*;

    fn parse(arguments: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("pam-biometrics").chain(arguments.iter().copied()))
    }

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn face_commands_parse() {
        let cli = parse(&["face", "enroll", "alice", "--add"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Face {
                command: FaceCommand::Enroll { user: Some(user), add: true }
            } if user == "alice"
        ));
        let cli = parse(&["face", "verify", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Face {
                command: FaceCommand::Verify {
                    user: None,
                    json: true
                }
            }
        ));
        let cli = parse(&["face", "delete", "alice", "bob"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Face { command: FaceCommand::Delete { users } } if users == &["alice", "bob"]
        ));
        let cli = parse(&["face", "status", "--service", "sudo"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Face {
                command: FaceCommand::Status { user: None, service: Some(service) }
            } if service == "sudo"
        ));
        let cli = parse(&["--socket", "/tmp/socket", "face", "scan", "alice"]).unwrap();
        assert_eq!(cli.socket, Path::new("/tmp/socket"));
        assert!(parse(&["face", "list"]).is_err());
        assert!(parse(&["face", "delete"]).is_err());
    }

    #[test]
    fn finger_commands_parse() {
        let cli = parse(&["finger", "enroll"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Finger {
                command: FingerCommand::Enroll { user: None, finger }
            } if finger == "right-index-finger"
        ));
        let cli = parse(&["finger", "enroll", "alice", "--finger", "left-thumb"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Finger {
                command: FingerCommand::Enroll { user: Some(user), finger }
            } if user == "alice" && finger == "left-thumb"
        ));
        let cli = parse(&["finger", "verify", "--json"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Finger {
                command: FingerCommand::Verify { user: None, finger, json: true }
            } if finger == "any"
        ));
        let cli = parse(&["finger", "verify", "bob", "-f", "right-thumb"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Finger {
                command: FingerCommand::Verify { user: Some(user), finger, json: false }
            } if user == "bob" && finger == "right-thumb"
        ));
        let cli = parse(&["finger", "delete", "alice", "bob", "--finger", "left-thumb"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Finger {
                command: FingerCommand::Delete { users, finger: Some(finger) }
            } if users == &["alice", "bob"] && finger == "left-thumb"
        ));
        let cli = parse(&["finger", "delete", "alice"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Finger {
                command: FingerCommand::Delete { finger: None, .. }
            }
        ));
        let cli = parse(&["finger", "list", "alice", "bob"]).unwrap();
        assert!(matches!(
            &cli.command,
            Command::Finger { command: FingerCommand::List { users } } if users == &["alice", "bob"]
        ));
        assert!(parse(&["finger", "list"]).is_err());
        assert!(parse(&["finger", "delete"]).is_err());
        assert!(parse(&["finger", "list", "alice", "--finger", "left-thumb"]).is_err());
        assert!(parse(&["finger", "scan"]).is_err());
    }

    #[test]
    fn top_level_face_commands_are_gone() {
        for name in [
            "enroll", "verify", "delete", "list", "scan", "status", "wait",
        ] {
            assert!(parse(&[name, "alice"]).is_err(), "{name}");
        }
    }

    #[test]
    fn other_commands_parse() {
        let cli = parse(&["policy", "show", "--service", "sudo", "--user", "alice"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Policy {
                command: PolicyCommand::Show { .. }
            }
        ));
        let cli = parse(&["pam-session", "--policy=/etc/other.json"]).unwrap();
        assert!(matches!(cli.command, Command::PamSession));
        assert_eq!(cli.policy, Path::new("/etc/other.json"));
        assert!(parse(&["pam-helper"]).is_err());
        assert!(parse(&["pam-session", "--prompt=Touch the reader."]).is_err());
    }
}
