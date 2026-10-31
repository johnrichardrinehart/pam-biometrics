//! Authorization of face model changes through polkit.

use std::collections::HashMap;
use std::time::Duration;

use zbus::blocking::{Connection, Proxy, connection};
use zbus::zvariant::Value;

/// Enroll the face of the caller.
pub const ACTION_ENROLL: &str = "io.github.johnrichardrinehart.pam-biometrics.face.enroll";
/// Delete the face of the caller.
pub const ACTION_DELETE: &str = "io.github.johnrichardrinehart.pam-biometrics.face.delete";
/// Enroll, delete, verify, or list the face of another user.
pub const ACTION_MANAGE_OTHER: &str =
    "io.github.johnrichardrinehart.pam-biometrics.face.manage-other";

/// The time that polkit gets for an authentication, for example a password
/// prompt.
const CHECK_TIMEOUT: Duration = Duration::from_secs(150);

/// `CheckAuthorizationFlags.AllowUserInteraction`.
const ALLOW_USER_INTERACTION: u32 = 1;

/// The client process of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    /// The UID from the peer credentials.
    pub uid: u32,
    /// The PID from the peer credentials.
    pub pid: u32,
}

/// Decides whether a caller can use an action.
pub trait Authority: Send + Sync + 'static {
    /// Returns true if polkit authorizes `caller` for `action`. An
    /// authentication prompt can block this call.
    fn check(&self, caller: Caller, action: &str) -> Result<bool, String>;
}

/// Returns the start time of a process, field 22 of `/proc/<pid>/stat`.
pub fn start_time(stat: &str) -> Option<u64> {
    // The command name in field 2 can contain spaces and parentheses. The
    // fields after the last ")" start with field 3.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// polkit on the system bus.
#[derive(Debug, Default)]
pub struct SystemAuthority;

impl SystemAuthority {
    fn connect() -> zbus::Result<Connection> {
        connection::Builder::system()?
            .method_timeout(CHECK_TIMEOUT)
            .build()
    }
}

impl Authority for SystemAuthority {
    fn check(&self, caller: Caller, action: &str) -> Result<bool, String> {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", caller.pid))
            .map_err(|error| format!("cannot read the start time of the caller: {error}"))?;
        let start = start_time(&stat).ok_or("the /proc stat of the caller is malformed")?;
        let uid = i32::try_from(caller.uid).map_err(|error| error.to_string())?;

        let connection = Self::connect().map_err(|error| error.to_string())?;
        let authority = Proxy::new(
            &connection,
            "org.freedesktop.PolicyKit1",
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
        )
        .map_err(|error| error.to_string())?;
        let subject: HashMap<&str, Value<'_>> = HashMap::from([
            ("pid", Value::U32(caller.pid)),
            ("start-time", Value::U64(start)),
            ("uid", Value::I32(uid)),
        ]);
        let details: HashMap<&str, &str> = HashMap::new();
        let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) = authority
            .call(
                "CheckAuthorization",
                &(
                    ("unix-process", subject),
                    action,
                    details,
                    ALLOW_USER_INTERACTION,
                    "",
                ),
            )
            .map_err(|error| error.to_string())?;
        Ok(authorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_time_from_stat() {
        let stat = "1234 (pam-biometrics) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 \
                    20 0 1 0 987654 12345678 300 18446744073709551615";
        assert_eq!(start_time(stat), Some(987_654));
        // A command name with spaces and a closing parenthesis.
        let stat = "77 (a) b (c)) R 1 77 77 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 0 0";
        assert_eq!(start_time(stat), Some(4242));
        assert_eq!(start_time("77 (short) R 1"), None);
        assert_eq!(start_time("no parenthesis"), None);
    }

    #[test]
    fn start_time_of_this_process() {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        assert!(start_time(&stat).is_some(), "{stat}");
    }
}
