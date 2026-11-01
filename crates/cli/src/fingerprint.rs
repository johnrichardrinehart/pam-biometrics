//! The fingerprint factor through fprintd on the system D-Bus.
//!
//! The factor verifies until a match, a reject, or a stop. After a device
//! error, a lost device, or a missing device, it starts again after a pause.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use pam_biometrics_policy::{Factor, Outcome};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

use crate::fprintd::{DEVICE_INTERFACE, MANAGER_INTERFACE, MANAGER_PATH, SERVICE};
use crate::session::{Event, FactorTask, Stop, pause};

/// The first pause before a new verification after an error. It doubles
/// up to [`MAX_BACKOFF`] while the errors repeat.
const MIN_BACKOFF: Duration = Duration::from_secs(1);

/// The longest pause before a new verification.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// The message after a wrong finger when tries remain.
pub const RETRY_MESSAGE: &str = "Fingerprint not recognized. Try again.";

/// What the factor does after a `VerifyStatus` signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Keep the verification. Show the message, if any.
    Wait(Option<&'static str>),
    /// Stop the verification and start a new one. Show the message.
    Restart(&'static str),
    /// End the factor with an outcome.
    Finish(Outcome),
}

/// Counts the tries of one verification.
#[derive(Clone, Copy, Debug)]
pub struct Tries {
    used: u32,
    max: u32,
}

impl Tries {
    /// Allows `max` wrong fingers before a reject.
    #[must_use]
    pub const fn new(max: u32) -> Self {
        Self { used: 0, max }
    }

    /// Returns the action for a `VerifyStatus(result, done)` signal.
    pub fn on_status(&mut self, result: &str, done: bool) -> Action {
        let retry = |message| {
            if done {
                Action::Restart(message)
            } else {
                Action::Wait(Some(message))
            }
        };
        match result {
            "verify-match" => Action::Finish(Outcome::Match),
            "verify-no-match" => {
                self.used += 1;
                if self.used >= self.max {
                    Action::Finish(Outcome::Reject)
                } else {
                    Action::Restart(RETRY_MESSAGE)
                }
            }
            "verify-retry-scan" => retry("Scan your finger again."),
            "verify-swipe-too-short" => retry("The swipe was too short. Try again."),
            "verify-finger-not-centered" => retry("Center your finger on the reader. Try again."),
            "verify-remove-and-retry" => retry("Remove your finger. Then try again."),
            // verify-disconnected, verify-unknown-error, and unknown results.
            _ => Action::Finish(Outcome::NoDecision),
        }
    }
}

#[derive(Default)]
struct Session {
    device: Option<Proxy<'static>>,
    claimed: bool,
    verifying: bool,
    stopped: bool,
}

impl Session {
    /// Stops the verification and releases the device. Errors do not matter
    /// here: the device is unusable or already free.
    fn release(&mut self) {
        if let Some(device) = &self.device {
            if self.verifying {
                let _: zbus::Result<()> = device.call("VerifyStop", &());
                self.verifying = false;
            }
            if self.claimed {
                let _: zbus::Result<()> = device.call("Release", &());
                self.claimed = false;
            }
        }
    }
}

type Shared = Arc<Mutex<Session>>;

fn lock(session: &Shared) -> MutexGuard<'_, Session> {
    session.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The fingerprint factor for one user.
#[derive(Debug)]
pub struct FingerprintTask {
    /// The user name for `Claim`.
    pub user: String,
    /// Wrong fingers before a reject.
    pub max_tries: u32,
}

struct FingerprintStop(Shared);

impl Stop for FingerprintStop {
    fn stop(self: Box<Self>) {
        let mut session = lock(&self.0);
        session.stopped = true;
        session.release();
    }
}

impl FactorTask for FingerprintTask {
    fn start(self: Box<Self>, events: Sender<Event>) -> Box<dyn Stop> {
        let session = Shared::default();
        let shared = Arc::clone(&session);
        thread::spawn(move || {
            // Wrong fingers count across restarts.
            let mut tries = Tries::new(self.max_tries);
            let mut backoff = MIN_BACKOFF;
            loop {
                let mut started = false;
                let outcome = verify(&shared, &self.user, &mut tries, &mut started, &events)
                    .unwrap_or(Outcome::NoDecision);
                lock(&shared).release();
                if outcome != Outcome::NoDecision {
                    let _ = events.send(Event::Finished(Factor::Fingerprint, outcome));
                    return;
                }
                if started {
                    backoff = MIN_BACKOFF;
                }
                if !pause(backoff, || lock(&shared).stopped) {
                    return;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        });
        Box::new(FingerprintStop(session))
    }
}

/// Starts a verification unless the step stopped the factor.
fn start_verify(session: &Shared) -> zbus::Result<bool> {
    let mut session = lock(session);
    if session.stopped {
        return Ok(false);
    }
    let device = session
        .device
        .as_ref()
        .expect("the device is set before verification");
    device.call::<_, _, ()>("VerifyStart", &("any",))?;
    session.verifying = true;
    Ok(true)
}

/// Verifies once. Returns [`Outcome::NoDecision`] after a device error or
/// a stop. Sets `started` when the verification started.
fn verify(
    session: &Shared,
    user: &str,
    tries: &mut Tries,
    started: &mut bool,
    events: &Sender<Event>,
) -> zbus::Result<Outcome> {
    let connection = Connection::system()?;
    let manager = Proxy::new(&connection, SERVICE, MANAGER_PATH, MANAGER_INTERFACE)?;
    let path: OwnedObjectPath = manager.call("GetDefaultDevice", &())?;
    let device = Proxy::new(&connection, SERVICE, path.into_inner(), DEVICE_INTERFACE)?;
    // Subscribe before VerifyStart, so that no signal gets lost.
    let mut statuses = device.receive_signal("VerifyStatus")?;
    {
        let mut guard = lock(session);
        if guard.stopped {
            return Ok(Outcome::NoDecision);
        }
        device.call::<_, _, ()>("Claim", &(user,))?;
        guard.device = Some(device);
        guard.claimed = true;
    }

    // "any" accepts every enrolled finger. Without it, fprintd checks only
    // the first enrolled finger.
    if !start_verify(session)? {
        return Ok(Outcome::NoDecision);
    }
    *started = true;
    for message in statuses.by_ref() {
        let (result, done): (String, bool) = message.body().deserialize()?;
        let action = tries.on_status(&result, done);
        match action {
            Action::Wait(message) => {
                if let Some(message) = message {
                    let _ = events.send(Event::Message(message.to_owned()));
                }
            }
            Action::Restart(message) => {
                let _ = events.send(Event::Message(message.to_owned()));
                {
                    let mut guard = lock(session);
                    if let Some(device) = &guard.device {
                        device.call::<_, _, ()>("VerifyStop", &())?;
                    }
                    guard.verifying = false;
                }
                if !start_verify(session)? {
                    return Ok(Outcome::NoDecision);
                }
            }
            Action::Finish(outcome) => return Ok(outcome),
        }
    }
    Ok(Outcome::NoDecision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_finishes() {
        let mut tries = Tries::new(3);
        assert_eq!(
            tries.on_status("verify-match", true),
            Action::Finish(Outcome::Match)
        );
    }

    #[test]
    fn wrong_finger_restarts_until_max_tries() {
        let mut tries = Tries::new(3);
        assert_eq!(
            tries.on_status("verify-no-match", true),
            Action::Restart(RETRY_MESSAGE)
        );
        assert_eq!(
            tries.on_status("verify-no-match", true),
            Action::Restart(RETRY_MESSAGE)
        );
        assert_eq!(
            tries.on_status("verify-no-match", true),
            Action::Finish(Outcome::Reject)
        );

        let mut once = Tries::new(1);
        assert_eq!(
            once.on_status("verify-no-match", true),
            Action::Finish(Outcome::Reject)
        );
    }

    #[test]
    fn match_after_wrong_finger() {
        let mut tries = Tries::new(3);
        assert_eq!(
            tries.on_status("verify-no-match", true),
            Action::Restart(RETRY_MESSAGE)
        );
        assert_eq!(
            tries.on_status("verify-match", true),
            Action::Finish(Outcome::Match)
        );
    }

    #[test]
    fn retry_statuses_do_not_use_tries() {
        let mut tries = Tries::new(1);
        for result in [
            "verify-retry-scan",
            "verify-swipe-too-short",
            "verify-finger-not-centered",
            "verify-remove-and-retry",
        ] {
            assert!(
                matches!(tries.on_status(result, false), Action::Wait(Some(_))),
                "{result}"
            );
            assert!(
                matches!(tries.on_status(result, true), Action::Restart(_)),
                "{result}"
            );
        }
        assert_eq!(
            tries.on_status("verify-no-match", true),
            Action::Finish(Outcome::Reject)
        );
    }

    #[test]
    fn device_errors_give_no_decision() {
        let mut tries = Tries::new(3);
        for result in [
            "verify-disconnected",
            "verify-unknown-error",
            "verify-something-new",
        ] {
            assert_eq!(
                tries.on_status(result, true),
                Action::Finish(Outcome::NoDecision),
                "{result}"
            );
        }
    }
}
