//! Factor outcomes, face classification, and the step decision.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::settings::{Combine, FaceSettings, Factor, OnNoDecision, Settings};

/// Helper exit code for [`StepOutcome::Success`].
pub const EXIT_SUCCESS: i32 = 0;
/// Helper exit code for [`StepOutcome::Reject`].
pub const EXIT_REJECT: i32 = 10;
/// Helper exit code for [`StepOutcome::NoDecision`].
pub const EXIT_NO_DECISION: i32 = 20;

/// The outcome of one factor, or the combined outcome of all factors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The factor identified the user.
    Match,
    /// The factor identified somebody else.
    Reject,
    /// The factor gave no decision.
    NoDecision,
}

/// The result of the PAM step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    /// `PAM_SUCCESS`.
    Success,
    /// `PAM_AUTH_ERR`.
    Reject,
    /// `PAM_IGNORE`.
    NoDecision,
}

impl StepOutcome {
    /// Returns the helper exit code that `pam_biometrics.so` maps to PAM.
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Success => EXIT_SUCCESS,
            Self::Reject => EXIT_REJECT,
            Self::NoDecision => EXIT_NO_DECISION,
        }
    }
}

/// The decision of the step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The combined factor outcome before `on_no_decision` applies.
    pub combined: Outcome,
    /// The step outcome after `on_no_decision` applies.
    pub outcome: StepOutcome,
}

impl Settings {
    /// Decides the step from the factors that finished.
    ///
    /// `finished` holds the outcome of each enabled factor that ended.
    /// After the deadline, a factor without an outcome counts as
    /// [`Outcome::NoDecision`]. The return value is `None` while the step
    /// must wait for more outcomes.
    #[must_use]
    pub fn decide(
        &self,
        finished: &BTreeMap<Factor, Outcome>,
        deadline_passed: bool,
    ) -> Option<Verdict> {
        if self.factors.is_empty() {
            return Some(Verdict {
                combined: Outcome::NoDecision,
                outcome: StepOutcome::NoDecision,
            });
        }
        let outcomes = || {
            self.factors
                .iter()
                .filter_map(|factor| finished.get(factor))
        };
        let all_finished = self
            .factors
            .iter()
            .all(|factor| finished.contains_key(factor));
        let any = |wanted: Outcome| outcomes().any(|outcome| *outcome == wanted);

        let combined = match self.combine {
            Combine::Any if any(Outcome::Match) => Outcome::Match,
            Combine::All if any(Outcome::Reject) => Outcome::Reject,
            Combine::All
                if all_finished && outcomes().all(|outcome| *outcome == Outcome::Match) =>
            {
                Outcome::Match
            }
            _ if !(all_finished || deadline_passed) => return None,
            Combine::Any if any(Outcome::Reject) => Outcome::Reject,
            _ => Outcome::NoDecision,
        };
        let outcome = match (combined, self.on_no_decision) {
            (Outcome::Match, _) => StepOutcome::Success,
            (Outcome::Reject, _) | (Outcome::NoDecision, OnNoDecision::Deny) => StepOutcome::Reject,
            (Outcome::NoDecision, OnNoDecision::Allow) => StepOutcome::NoDecision,
        };
        Some(Verdict { combined, outcome })
    }
}

/// The class of a face scan result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaceClass {
    /// The best distance is at or below the match distance.
    Match,
    /// The best distance is between the match and the reject distance.
    Uncertain,
    /// Enough frames had a face and every face is beyond the reject distance.
    Reject,
    /// Too few frames had a face.
    Absent,
}

impl FaceClass {
    /// Returns the factor outcome of this class.
    #[must_use]
    pub const fn outcome(self) -> Outcome {
        match self {
            Self::Match => Outcome::Match,
            Self::Reject => Outcome::Reject,
            Self::Uncertain | Self::Absent => Outcome::NoDecision,
        }
    }
}

impl FaceSettings {
    /// Classifies a scan from its best distance and the number of frames
    /// with a face.
    #[must_use]
    pub fn classify(&self, best: Option<f64>, faces: u32) -> FaceClass {
        match best {
            Some(best) if best <= self.match_distance => FaceClass::Match,
            Some(best) if best <= self.reject_distance => FaceClass::Uncertain,
            Some(_) if faces >= self.min_reject_frames => FaceClass::Reject,
            _ => FaceClass::Absent,
        }
    }
}
