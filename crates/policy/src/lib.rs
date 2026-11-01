//! Policy for the pam-biometrics PAM step.
//!
//! A policy file sets the enabled factors, how the step combines their
//! outcomes, and the thresholds of each factor. Settings resolve for a
//! (service, user) pair. [`Settings::decide`] turns factor outcomes into a
//! step outcome without side effects.

mod decision;
mod policy;
mod settings;

pub use decision::{
    EXIT_NO_DECISION, EXIT_REJECT, EXIT_SUCCESS, FaceClass, Outcome, StepOutcome, Verdict,
};
pub use policy::{DEFAULT_POLICY_PATH, Error, POLICY_VERSION, Policy, UserPolicy};
pub use settings::{
    AfterPassword, Combine, FaceLayer, FaceSettings, Factor, FingerprintLayer, FingerprintSettings,
    Layer, OnNoDecision, Settings,
};

#[cfg(test)]
mod tests;
