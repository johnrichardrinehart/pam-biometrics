//! `pam_biometrics.so`: runs the pam-biometrics helper for the auth step.
//!
//! Usage: `auth [success=ok ignore=ignore default=die] pam_biometrics.so [ARGS...]`
//!
//! The module runs `pam-biometrics pam-helper ARGS...` from a path that the
//! build sets. The environment of the helper contains only `PAM_USER`,
//! `PAM_SERVICE`, and `PAM_TYPE=auth`. Each non-empty line on the standard
//! output of the helper goes to the application as an information message.
//! The exit status of the helper gives the result:
//!
//! | Exit status | Meaning             | Result         |
//! |-------------|---------------------|----------------|
//! | 0           | A match.            | `PAM_SUCCESS`  |
//! | 10          | A reject.           | `PAM_AUTH_ERR` |
//! | other       | No decision.        | `PAM_IGNORE`   |
//!
//! A crash of the helper or of this module gives no decision, so that a
//! fault cannot lock the user out. The password stays necessary in the rest
//! of the stack.

use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_void};
use std::io::{BufRead as _, BufReader};
use std::os::unix::ffi::OsStrExt as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::{Command, Stdio};

/// The helper program. The Nix build sets the store path.
const HELPER: &str = match option_env!("PAM_BIOMETRICS_HELPER") {
    Some(path) => path,
    None => "/usr/bin/pam-biometrics",
};

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_IGNORE: c_int = 25;
const PAM_SERVICE: c_int = 1;
const PAM_TEXT_INFO: c_int = 4;
const LOG_ERR: c_int = 3;
const LOG_WARNING: c_int = 4;

const HELPER_MATCH: i32 = 0;
const HELPER_REJECT: i32 = 10;

/// The opaque `pam_handle_t`.
#[repr(C)]
#[derive(Debug)]
pub struct PamHandle {
    _private: [u8; 0],
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_prompt(
        pamh: *mut PamHandle,
        style: c_int,
        response: *mut *mut c_char,
        fmt: *const c_char,
        ...
    ) -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

/// Maps the exit code of the helper to a PAM result. `None` stands for a
/// termination by a signal.
const fn pam_result(code: Option<i32>) -> c_int {
    match code {
        Some(HELPER_MATCH) => PAM_SUCCESS,
        Some(HELPER_REJECT) => PAM_AUTH_ERR,
        _ => PAM_IGNORE,
    }
}

/// Converts the module arguments to helper arguments.
///
/// # Safety
///
/// `argv` must point to `argc` valid C strings, or `argc` must be 0.
unsafe fn arguments<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a OsStr> {
    let count = usize::try_from(argc).unwrap_or(0);
    if count == 0 || argv.is_null() {
        return Vec::new();
    }
    // SAFETY: The caller guarantees `count` valid pointers.
    let pointers = unsafe { std::slice::from_raw_parts(argv, count) };
    pointers
        .iter()
        .filter(|pointer| !pointer.is_null())
        // SAFETY: Each pointer is a valid C string.
        .map(|pointer| OsStr::from_bytes(unsafe { CStr::from_ptr(*pointer) }.to_bytes()))
        .collect()
}

fn log(pamh: *mut PamHandle, priority: c_int, message: &str) {
    if let Ok(message) = CString::new(message) {
        // SAFETY: `pamh` is the handle of this call. The format consumes one
        // C string.
        unsafe { pam_syslog(pamh, priority, c"%s".as_ptr(), message.as_ptr()) };
    }
}

fn info(pamh: *mut PamHandle, line: &[u8]) {
    if let Ok(line) = CString::new(line) {
        // SAFETY: `pamh` is the handle of this call. The format consumes one
        // C string. PAM_TEXT_INFO needs no response.
        unsafe {
            pam_prompt(
                pamh,
                PAM_TEXT_INFO,
                std::ptr::null_mut(),
                c"%s".as_ptr(),
                line.as_ptr(),
            )
        };
    }
}

/// # Safety
///
/// `pamh` must be a valid PAM handle. `argv` must hold `argc` C strings.
unsafe fn authenticate(pamh: *mut PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    let mut user: *const c_char = std::ptr::null();
    // SAFETY: `pamh` is valid. `user` receives a string that PAM owns.
    if unsafe { pam_get_user(pamh, &raw mut user, std::ptr::null()) } != PAM_SUCCESS
        || user.is_null()
    {
        return PAM_IGNORE;
    }
    // SAFETY: PAM returned a valid C string.
    let user = OsStr::from_bytes(unsafe { CStr::from_ptr(user) }.to_bytes());

    let mut service: *const c_void = std::ptr::null();
    // SAFETY: `pamh` is valid. PAM_SERVICE is a C string that PAM owns.
    let service = if unsafe { pam_get_item(pamh, PAM_SERVICE, &raw mut service) } == PAM_SUCCESS
        && !service.is_null()
    {
        // SAFETY: PAM_SERVICE is a C string.
        OsStr::from_bytes(unsafe { CStr::from_ptr(service.cast()) }.to_bytes())
    } else {
        OsStr::new("")
    };

    let child = Command::new(HELPER)
        .arg("pam-helper")
        // SAFETY: The caller guarantees `argc` and `argv`.
        .args(unsafe { arguments(argc, argv) })
        .env_clear()
        .env("PAM_USER", user)
        .env("PAM_SERVICE", service)
        .env("PAM_TYPE", "auth")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            log(pamh, LOG_ERR, &format!("cannot run {HELPER}: {error}"));
            return PAM_IGNORE;
        }
    };

    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).split(b'\n') {
            let Ok(line) = line else {
                break;
            };
            if !line.is_empty() {
                info(pamh, &line);
            }
        }
    }

    match child.wait() {
        Ok(status) => {
            let result = pam_result(status.code());
            if result == PAM_IGNORE {
                log(
                    pamh,
                    LOG_WARNING,
                    &format!("helper gave no decision ({status})"),
                );
            }
            result
        }
        Err(error) => {
            log(pamh, LOG_ERR, &format!("waitpid: {error}"));
            PAM_IGNORE
        }
    }
}

/// The auth entry point.
///
/// # Safety
///
/// PAM calls this function with a valid handle and arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: PAM passes a valid handle and arguments.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        authenticate(pamh, argc, argv)
    }))
    .unwrap_or(PAM_IGNORE)
}

/// The credential entry point. This module sets no credentials.
///
/// # Safety
///
/// PAM calls this function with a valid handle and arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_map_to_pam_results() {
        assert_eq!(pam_result(Some(0)), PAM_SUCCESS);
        assert_eq!(pam_result(Some(10)), PAM_AUTH_ERR);
        assert_eq!(pam_result(Some(20)), PAM_IGNORE);
        assert_eq!(pam_result(Some(1)), PAM_IGNORE);
        assert_eq!(pam_result(Some(127)), PAM_IGNORE);
        assert_eq!(pam_result(None), PAM_IGNORE);
    }

    #[test]
    fn module_arguments() {
        let first = c"--prompt=Touch the reader.";
        let second = c"--policy=/etc/other.json";
        let argv = [first.as_ptr(), second.as_ptr()];
        // SAFETY: `argv` holds two valid C strings.
        let converted = unsafe { arguments(2, argv.as_ptr()) };
        assert_eq!(
            converted,
            [
                OsStr::new("--prompt=Touch the reader."),
                OsStr::new("--policy=/etc/other.json")
            ]
        );
        // SAFETY: A count of 0 does not read `argv`.
        assert!(unsafe { arguments(0, std::ptr::null()) }.is_empty());
    }

    #[test]
    fn setcred_ignores() {
        // SAFETY: The function does not use its arguments.
        let result = unsafe { pam_sm_setcred(std::ptr::null_mut(), 0, 0, std::ptr::null()) };
        assert_eq!(result, PAM_IGNORE);
    }
}
