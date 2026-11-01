//! The policy file, its resolution for a (service, user) pair, and its
//! validation.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::settings::{Factor, Layer, Settings};

/// The default location of the policy file.
pub const DEFAULT_POLICY_PATH: &str = "/etc/pam-biometrics/policy.json";

/// The policy file format version that this crate reads.
pub const POLICY_VERSION: u32 = 1;

/// An error in a policy file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file exists but is not readable.
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The policy file.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The text is not a valid policy document.
    #[error("{origin}: {source}")]
    Parse {
        /// The policy file or another description of the input.
        origin: String,
        /// The cause.
        source: serde_json::Error,
    },
    /// The document is valid JSON with a value that the policy forbids.
    #[error("{origin}: {context}: {message}")]
    Invalid {
        /// The policy file or another description of the input.
        origin: String,
        /// The location of the value.
        context: String,
        /// What is wrong.
        message: String,
    },
}

/// Overrides for one user.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPolicy {
    /// Applies to every service for this user.
    #[serde(default, skip_serializing_if = "is_empty_layer")]
    pub defaults: Layer,
    /// Applies to one service for this user.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, Layer>,
}

/// A policy document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The format version. Only [`POLICY_VERSION`] is valid.
    pub version: u32,
    /// Applies to every service and user.
    #[serde(default, skip_serializing_if = "is_empty_layer")]
    pub defaults: Layer,
    /// Applies to one PAM service.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, Layer>,
    /// Applies to one user.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub users: BTreeMap<String, UserPolicy>,
}

fn is_empty_layer(layer: &Layer) -> bool {
    *layer == Layer::default()
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: POLICY_VERSION,
            defaults: Layer::default(),
            services: BTreeMap::new(),
            users: BTreeMap::new(),
        }
    }
}

impl Policy {
    /// Parses and validates a policy document. `origin` names the input in
    /// error messages.
    pub fn parse(text: &str, origin: &str) -> Result<Self, Error> {
        let policy: Self = serde_json::from_str(text).map_err(|source| Error::Parse {
            origin: origin.to_owned(),
            source,
        })?;
        policy.validate(origin)?;
        Ok(policy)
    }

    /// Reads, parses, and validates the policy file at `path`. A missing file
    /// gives the built-in defaults.
    pub fn load(path: &Path) -> Result<Self, Error> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, &path.display().to_string()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(Error::Read {
                path: path.to_owned(),
                source,
            }),
        }
    }

    /// Resolves the settings for a service and a user. The layers apply in
    /// this order: built-in defaults, `defaults`, `services[service]`,
    /// `users[user].defaults`, `users[user].services[service]`.
    #[must_use]
    pub fn resolve(&self, service: Option<&str>, user: Option<&str>) -> Settings {
        let mut settings = Settings::default();
        settings.apply(&self.defaults);
        if let Some(layer) = service.and_then(|service| self.services.get(service)) {
            settings.apply(layer);
        }
        if let Some(overrides) = user.and_then(|user| self.users.get(user)) {
            settings.apply(&overrides.defaults);
            if let Some(layer) = service.and_then(|service| overrides.services.get(service)) {
                settings.apply(layer);
            }
        }
        settings
    }

    /// Returns every service name that the policy lists, at the top level or
    /// for a user.
    fn service_names(&self) -> BTreeSet<&str> {
        self.services
            .keys()
            .chain(self.users.values().flat_map(|user| user.services.keys()))
            .map(String::as_str)
            .collect()
    }

    /// Returns every (service, user) pair that can resolve to distinct
    /// settings. `None` stands for a name that the policy does not list.
    fn contexts(&self) -> Vec<(Option<&str>, Option<&str>)> {
        let services: Vec<Option<&str>> = std::iter::once(None)
            .chain(self.service_names().into_iter().map(Some))
            .collect();
        let users: Vec<Option<&str>> = std::iter::once(None)
            .chain(self.users.keys().map(|user| Some(user.as_str())))
            .collect();
        services
            .iter()
            .flat_map(|service| users.iter().map(move |user| (*service, *user)))
            .collect()
    }

    /// Returns the smallest face match distance over all services for
    /// `user`. A scan that reaches this distance is a match for every
    /// service, so the daemon can stop it early.
    #[must_use]
    pub fn strictest_match_distance(&self, user: &str) -> f64 {
        let services = std::iter::once(None).chain(self.service_names().into_iter().map(Some));
        let mut strictest: Option<f64> = None;
        for service in services {
            let settings = self.resolve(service, Some(user));
            if settings.enabled(Factor::Face) {
                let distance = settings.face.match_distance;
                strictest = Some(strictest.map_or(distance, |current| current.min(distance)));
            }
        }
        strictest.unwrap_or_else(|| self.resolve(None, Some(user)).face.match_distance)
    }

    /// Checks the version, every layer, and every resolved combination.
    pub fn validate(&self, origin: &str) -> Result<(), Error> {
        let invalid = |context: &str, message: String| Error::Invalid {
            origin: origin.to_owned(),
            context: context.to_owned(),
            message,
        };
        if self.version != POLICY_VERSION {
            return Err(invalid(
                "version",
                format!("must be {POLICY_VERSION}, not {}", self.version),
            ));
        }

        let mut layers: Vec<(String, &Layer)> = vec![("defaults".to_owned(), &self.defaults)];
        for (service, layer) in &self.services {
            layers.push((format!("services.{service}"), layer));
        }
        for (user, overrides) in &self.users {
            layers.push((format!("users.{user}.defaults"), &overrides.defaults));
            for (service, layer) in &overrides.services {
                layers.push((format!("users.{user}.services.{service}"), layer));
            }
        }
        for (context, layer) in layers {
            check_layer(layer).map_err(|message| invalid(&context, message))?;
        }

        for (service, user) in self.contexts() {
            let settings = self.resolve(service, user);
            check_settings(&settings).map_err(|message| {
                let context = match (service, user) {
                    (Some(service), Some(user)) => {
                        format!("resolved settings for service {service} and user {user}")
                    }
                    (Some(service), None) => format!("resolved settings for service {service}"),
                    (None, Some(user)) => format!("resolved settings for user {user}"),
                    (None, None) => "resolved settings".to_owned(),
                };
                invalid(&context, message)
            })?;
        }
        Ok(())
    }
}

fn check_layer(layer: &Layer) -> Result<(), String> {
    if let Some(factors) = &layer.factors {
        let mut seen = BTreeSet::new();
        for factor in factors {
            if !seen.insert(factor) {
                return Err(format!("factors lists {factor} more than once"));
            }
        }
    }
    if layer.timeout_seconds == Some(0) {
        return Err("timeout_seconds must be at least 1".to_owned());
    }
    for (name, text) in [
        ("password_prompt", &layer.password_prompt),
        ("wait_message", &layer.wait_message),
        ("after_password_prompt", &layer.after_password_prompt),
    ] {
        if let Some(text) = text {
            if text.trim().is_empty() {
                return Err(format!("{name} must contain text"));
            }
            check_line(name, text)?;
        }
    }
    if let Some(fingerprint) = &layer.fingerprint
        && fingerprint.max_tries == Some(0)
    {
        return Err("fingerprint.max_tries must be at least 1".to_owned());
    }
    if let Some(face) = &layer.face {
        for (name, value) in [
            ("match_distance", face.match_distance),
            ("reject_distance", face.reject_distance),
        ] {
            if let Some(value) = value
                && !(value.is_finite() && value > 0.0)
            {
                return Err(format!("face.{name} must be greater than 0"));
            }
        }
        if face.min_reject_frames == Some(0) {
            return Err("face.min_reject_frames must be at least 1".to_owned());
        }
        if let Some(trigger) = &face.trigger {
            check_line("face.trigger", trigger)?;
        }
    }
    Ok(())
}

/// The PAM module and the helper exchange these texts as lines, so they
/// cannot contain line breaks or other control characters.
fn check_line(name: &str, text: &str) -> Result<(), String> {
    if text.chars().any(char::is_control) {
        return Err(format!("{name} must not contain control characters"));
    }
    Ok(())
}

fn check_settings(settings: &Settings) -> Result<(), String> {
    let face = &settings.face;
    if face.match_distance > face.reject_distance {
        return Err(format!(
            "face.match_distance ({}) is greater than face.reject_distance ({})",
            face.match_distance, face.reject_distance
        ));
    }
    Ok(())
}
