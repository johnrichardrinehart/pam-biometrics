//! Resolved settings and the partial layers that a policy file contains.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// A biometric factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Factor {
    /// A finger on the reader that fprintd manages.
    Fingerprint,
    /// A face scan from the pam-biometricsd daemon.
    Face,
}

impl Factor {
    /// Returns the name that the policy file uses.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fingerprint => "fingerprint",
            Self::Face => "face",
        }
    }
}

impl fmt::Display for Factor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How the step combines the outcomes of the enabled factors.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Combine {
    /// One match is sufficient.
    #[default]
    Any,
    /// Every enabled factor must match.
    All,
}

/// What the step does when no factor gives a decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnNoDecision {
    /// Return `PAM_IGNORE`. The rest of the stack decides.
    #[default]
    Allow,
    /// Treat the attempt as a reject.
    Deny,
}

/// Resolved settings of the fingerprint factor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintSettings {
    /// Number of finger scans before a wrong finger rejects the attempt.
    pub max_tries: u32,
}

/// Resolved settings of the face factor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaceSettings {
    /// A best distance at or below this value is a match.
    pub match_distance: f64,
    /// A best distance above this value can reject the attempt.
    pub reject_distance: f64,
    /// A reject needs a face in at least this many frames.
    pub min_reject_frames: u32,
}

/// Settings for one (service, user) pair after the resolution of all layers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The enabled factors.
    pub factors: Vec<Factor>,
    /// How the step combines the factor outcomes.
    pub combine: Combine,
    /// What the step does without a decision.
    pub on_no_decision: OnNoDecision,
    /// Maximum time that the step waits for the factors.
    pub timeout_seconds: u32,
    /// Text that the step shows when it starts to wait.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Fingerprint settings.
    pub fingerprint: FingerprintSettings,
    /// Face settings.
    pub face: FaceSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            factors: vec![Factor::Fingerprint, Factor::Face],
            combine: Combine::Any,
            on_no_decision: OnNoDecision::Allow,
            timeout_seconds: 15,
            prompt: None,
            fingerprint: FingerprintSettings { max_tries: 3 },
            face: FaceSettings {
                match_distance: 0.45,
                reject_distance: 0.6,
                min_reject_frames: 3,
            },
        }
    }
}

impl Settings {
    /// Applies the values that `layer` sets. Lists replace, objects merge.
    pub fn apply(&mut self, layer: &Layer) {
        if let Some(factors) = &layer.factors {
            self.factors.clone_from(factors);
        }
        if let Some(combine) = layer.combine {
            self.combine = combine;
        }
        if let Some(on_no_decision) = layer.on_no_decision {
            self.on_no_decision = on_no_decision;
        }
        if let Some(timeout) = layer.timeout_seconds {
            self.timeout_seconds = timeout;
        }
        if let Some(prompt) = &layer.prompt {
            self.prompt = Some(prompt.clone());
        }
        if let Some(fingerprint) = &layer.fingerprint
            && let Some(max_tries) = fingerprint.max_tries
        {
            self.fingerprint.max_tries = max_tries;
        }
        if let Some(face) = &layer.face {
            if let Some(distance) = face.match_distance {
                self.face.match_distance = distance;
            }
            if let Some(distance) = face.reject_distance {
                self.face.reject_distance = distance;
            }
            if let Some(frames) = face.min_reject_frames {
                self.face.min_reject_frames = frames;
            }
        }
    }

    /// Returns true if `factor` is enabled.
    #[must_use]
    pub fn enabled(&self, factor: Factor) -> bool {
        self.factors.contains(&factor)
    }
}

/// Deserializes a present value. A JSON `null` is an error, not an unset field.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// A partial settings object. Each field that a layer sets replaces the
/// value of the lower layers.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    /// See [`Settings::factors`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub factors: Option<Vec<Factor>>,
    /// See [`Settings::combine`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub combine: Option<Combine>,
    /// See [`Settings::on_no_decision`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub on_no_decision: Option<OnNoDecision>,
    /// See [`Settings::timeout_seconds`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub timeout_seconds: Option<u32>,
    /// See [`Settings::prompt`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub prompt: Option<String>,
    /// See [`Settings::fingerprint`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub fingerprint: Option<FingerprintLayer>,
    /// See [`Settings::face`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub face: Option<FaceLayer>,
}

/// A partial [`FingerprintSettings`] object.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintLayer {
    /// See [`FingerprintSettings::max_tries`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_tries: Option<u32>,
}

/// A partial [`FaceSettings`] object.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaceLayer {
    /// See [`FaceSettings::match_distance`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub match_distance: Option<f64>,
    /// See [`FaceSettings::reject_distance`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub reject_distance: Option<f64>,
    /// See [`FaceSettings::min_reject_frames`].
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_reject_frames: Option<u32>,
}
