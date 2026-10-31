//! A polkit text agent for commands that need authorization.
//!
//! A desktop session without a polkit agent cannot show a password prompt.
//! For commands that change face or finger enrollments, this program starts
//! pkttyagent for its own process when stdin is a terminal. polkit then
//! asks for the password in the terminal.

use std::fs::File;
use std::io::{IsTerminal as _, Read as _};
use std::os::fd::AsRawFd as _;
use std::process::{Child, Command};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::unistd::pipe2;

/// The pkttyagent program. The Nix build sets the store path.
const PKTTYAGENT: &str = match option_env!("PAM_BIOMETRICS_PKTTYAGENT") {
    Some(path) => path,
    None => "pkttyagent",
};

/// A running pkttyagent. Dropping it stops the agent.
#[derive(Debug)]
pub struct TtyAgent {
    child: Child,
}

impl TtyAgent {
    /// Starts pkttyagent for this process if stdin is a terminal. Returns
    /// `None` without a terminal or if the agent does not start.
    pub fn start_for_terminal() -> Option<Self> {
        if !std::io::stdin().is_terminal() {
            return None;
        }
        match Self::start() {
            Ok(agent) => Some(agent),
            Err(error) => {
                eprintln!("pam-biometrics: cannot start {PKTTYAGENT}: {error}");
                None
            }
        }
    }

    fn start() -> std::io::Result<Self> {
        // pkttyagent closes the notify descriptor after it registers. Only
        // the write end goes to the child.
        let (read, write) = pipe2(OFlag::O_CLOEXEC)?;
        fcntl(&write, FcntlArg::F_SETFD(FdFlag::empty()))?;
        let child = Command::new(PKTTYAGENT)
            .arg("--process")
            .arg(std::process::id().to_string())
            .arg("--notify-fd")
            .arg(write.as_raw_fd().to_string())
            .arg("--fallback")
            .spawn()?;
        drop(write);
        // Wait for the registration. The read also ends if the agent exits.
        let mut byte = [0];
        let _ = File::from(read).read(&mut byte);
        Ok(Self { child })
    }
}

impl Drop for TtyAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
