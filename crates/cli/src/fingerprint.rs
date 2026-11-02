//! The fingerprint factor through fprintd on the system D-Bus.
//!
//! The factor verifies until a match, a reject, or a stop. After a device
//! error, it starts a new verification on the same claim after a pause.
//! After a bus error or a missing device, it releases the device and claims
//! it again after a pause.
//!
//! The factor never releases the device because of a device error. A
//! suspend cancels a running verification with a device error, and a
//! `Release` during the suspend fails in libfprint while fprintd forgets
//! the claim anyway: the device stays open, and every later `Claim` fails
//! with "The device has already been opened!" until fprintd exits.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use pam_biometrics_policy::{Factor, Outcome};
use zbus::blocking::proxy::SignalIterator;
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
    /// The device failed. Keep the claim, pause, and start a new
    /// verification.
    Fail,
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
            _ => Action::Fail,
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
            let mut backoff = Backoff::default();
            loop {
                let outcome = verify(&shared, &self.user, &mut tries, &mut backoff, &events)
                    .unwrap_or(Outcome::NoDecision);
                lock(&shared).release();
                if outcome != Outcome::NoDecision {
                    let _ = events.send(Event::Finished(Factor::Fingerprint, outcome));
                    return;
                }
                if !backoff.pause(&shared) {
                    return;
                }
            }
        });
        Box::new(FingerprintStop(session))
    }
}

/// The pause before a new verification after an error.
struct Backoff(Duration);

impl Default for Backoff {
    fn default() -> Self {
        Self(MIN_BACKOFF)
    }
}

impl Backoff {
    /// A verification started: the next pause is the shortest again.
    fn reset(&mut self) {
        self.0 = MIN_BACKOFF;
    }

    /// Pauses, then doubles the next pause. Returns false if the step
    /// stopped the factor.
    fn pause(&mut self, session: &Shared) -> bool {
        let resumed = pause(self.0, || lock(session).stopped);
        self.0 = (self.0 * 2).min(MAX_BACKOFF);
        resumed
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
    // "any" accepts every enrolled finger. Without it, fprintd checks only
    // the first enrolled finger.
    device.call::<_, _, ()>("VerifyStart", &("any",))?;
    session.verifying = true;
    Ok(true)
}

/// Stops the verification and keeps the claim.
fn stop_verify(session: &Shared) -> zbus::Result<()> {
    let mut guard = lock(session);
    if let Some(device) = &guard.device {
        device.call::<_, _, ()>("VerifyStop", &())?;
    }
    guard.verifying = false;
    Ok(())
}

/// How one verification ended.
enum Ended {
    /// A match, a reject, or no decision after a stop or a lost fprintd.
    Outcome(Outcome),
    /// The device failed. The claim is still valid.
    DeviceError,
}

/// Claims the device and verifies until an outcome. After a device error,
/// it keeps the claim and starts a new verification after a pause. Returns
/// [`Outcome::NoDecision`] after a stop or a lost fprintd, and an error
/// after a bus error. The caller releases the device in every case.
fn verify(
    session: &Shared,
    user: &str,
    tries: &mut Tries,
    backoff: &mut Backoff,
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

    loop {
        if !start_verify(session)? {
            return Ok(Outcome::NoDecision);
        }
        backoff.reset();
        match watch(session, &mut statuses, tries, events)? {
            Ended::Outcome(outcome) => return Ok(outcome),
            Ended::DeviceError => {
                stop_verify(session)?;
                if !backoff.pause(session) {
                    return Ok(Outcome::NoDecision);
                }
            }
        }
    }
}

/// Follows a started verification until it ends.
fn watch(
    session: &Shared,
    statuses: &mut SignalIterator<'_>,
    tries: &mut Tries,
    events: &Sender<Event>,
) -> zbus::Result<Ended> {
    for message in statuses.by_ref() {
        let (result, done): (String, bool) = message.body().deserialize()?;
        match tries.on_status(&result, done) {
            Action::Wait(message) => {
                if let Some(message) = message {
                    let _ = events.send(Event::Message(message.to_owned()));
                }
            }
            Action::Restart(message) => {
                let _ = events.send(Event::Message(message.to_owned()));
                stop_verify(session)?;
                if !start_verify(session)? {
                    return Ok(Ended::Outcome(Outcome::NoDecision));
                }
            }
            Action::Finish(outcome) => return Ok(Ended::Outcome(outcome)),
            Action::Fail => return Ok(Ended::DeviceError),
        }
    }
    // The bus closed the stream: fprintd is gone.
    Ok(Ended::Outcome(Outcome::NoDecision))
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
    fn device_errors_keep_the_claim() {
        let mut tries = Tries::new(1);
        for result in [
            "verify-disconnected",
            "verify-unknown-error",
            "verify-something-new",
        ] {
            assert_eq!(tries.on_status(result, true), Action::Fail, "{result}");
        }
        assert_eq!(
            tries.on_status("verify-no-match", true),
            Action::Finish(Outcome::Reject)
        );
    }
}
