//! Face model files: `<state-dir>/<user>.json`.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use pam_biometrics_face::ENCODING_LENGTH;
use serde::{Deserialize, Serialize};

/// The model file format version.
pub const MODEL_VERSION: u32 = 1;

/// `enroll --add` keeps at most this many samples and drops the oldest.
pub const MAX_MODEL_SAMPLES: usize = 30;

/// An encoding of one face sample.
pub type Encoding = Vec<f64>;

#[derive(Debug, Serialize, Deserialize)]
struct ModelFile {
    version: u32,
    encodings: Vec<Encoding>,
}

/// Returns the model path of `user`.
fn path(state_dir: &Path, user: &str) -> PathBuf {
    state_dir.join(format!("{user}.json"))
}

/// Rejects user names that do not map to one file in the state directory.
fn check_name(user: &str) -> io::Result<()> {
    if user.is_empty() || user.starts_with('.') || user.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("user name {user:?} is not usable as a file name"),
        ));
    }
    Ok(())
}

/// Reads the samples of `user`. Returns `None` if the user has no model.
pub fn load(state_dir: &Path, user: &str) -> io::Result<Option<Vec<Encoding>>> {
    check_name(user)?;
    let path = path(state_dir, user);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let invalid = |message: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {message}", path.display()),
        )
    };
    let model: ModelFile =
        serde_json::from_str(&text).map_err(|error| invalid(error.to_string()))?;
    if model.version != MODEL_VERSION {
        return Err(invalid(format!("unsupported version {}", model.version)));
    }
    if model.encodings.is_empty() {
        return Err(invalid("no encodings".to_owned()));
    }
    if let Some(encoding) = model
        .encodings
        .iter()
        .find(|encoding| encoding.len() != ENCODING_LENGTH)
    {
        return Err(invalid(format!(
            "an encoding has {} values, not {ENCODING_LENGTH}",
            encoding.len()
        )));
    }
    Ok(Some(model.encodings))
}

/// Replaces the model of `user`. The file has mode 0600. A rename makes the
/// change atomic.
pub fn store(state_dir: &Path, user: &str, encodings: Vec<Encoding>) -> io::Result<()> {
    check_name(user)?;
    let path = path(state_dir, user);
    let temporary = state_dir.join(format!(".{user}.json.tmp"));
    let mut text = serde_json::to_vec(&ModelFile {
        version: MODEL_VERSION,
        encodings,
    })
    .map_err(io::Error::other)?;
    text.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&text)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)
}

/// Removes the model of `user`. Returns false if no model existed.
pub fn remove(state_dir: &Path, user: &str) -> io::Result<bool> {
    check_name(user)?;
    match fs::remove_file(path(state_dir, user)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Appends `added` to `existing` and keeps the newest [`MAX_MODEL_SAMPLES`].
#[must_use]
pub fn merge(mut existing: Vec<Encoding>, added: Vec<Encoding>) -> Vec<Encoding> {
    existing.extend(added);
    let excess = existing.len().saturating_sub(MAX_MODEL_SAMPLES);
    existing.drain(..excess);
    existing
}

/// Picks at most `max` samples at even intervals, first sample included.
#[must_use]
pub fn pick_evenly<T: Clone>(samples: &[T], max: usize) -> Vec<T> {
    let count = samples.len().min(max);
    (0..count)
        .map(|index| samples[index * samples.len() / count].clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("pam-biometricsd-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn encoding(value: f64) -> Encoding {
        vec![value; ENCODING_LENGTH]
    }

    #[test]
    fn store_and_load() {
        let dir = TempDir::new("store");
        assert_eq!(load(&dir.0, "alice").unwrap(), None);
        store(&dir.0, "alice", vec![encoding(0.25), encoding(-0.5)]).unwrap();
        let mode = fs::metadata(dir.0.join("alice.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            load(&dir.0, "alice").unwrap(),
            Some(vec![encoding(0.25), encoding(-0.5)])
        );
        assert!(!dir.0.join(".alice.json.tmp").exists());
        assert!(remove(&dir.0, "alice").unwrap());
        assert!(!remove(&dir.0, "alice").unwrap());
    }

    #[test]
    fn loads_files_that_python_json_dump_writes() {
        let dir = TempDir::new("json-dump");
        // json.dump({"version": 1, "encodings": [...]}) writes this layout.
        let values: Vec<String> = (0..ENCODING_LENGTH)
            .map(|index| {
                format!(
                    "{}",
                    -0.1 + f64::from(u32::try_from(index).unwrap()) * 0.001
                )
            })
            .collect();
        let text = format!(
            "{{\"version\": 1, \"encodings\": [[{}], [{}]]}}",
            values.join(", "),
            values.join(", ")
        );
        fs::write(dir.0.join("bob.json"), text).unwrap();
        let model = load(&dir.0, "bob").unwrap().unwrap();
        assert_eq!(model.len(), 2);
        assert!((model[0][0] + 0.1).abs() < 1e-12);
    }

    #[test]
    fn rejects_invalid_files() {
        let dir = TempDir::new("invalid");
        for text in [
            "not json",
            r#"{"version": 2, "encodings": [[0.1]]}"#,
            r#"{"version": 1, "encodings": []}"#,
            r#"{"version": 1, "encodings": [[0.1, 0.2]]}"#,
        ] {
            fs::write(dir.0.join("carol.json"), text).unwrap();
            assert_eq!(
                load(&dir.0, "carol").unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{text}"
            );
        }
    }

    #[test]
    fn rejects_unsafe_names() {
        let dir = TempDir::new("names");
        for name in ["", ".hidden", "../etc", "a/b"] {
            assert_eq!(
                load(&dir.0, name).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn merge_keeps_the_newest() {
        let existing: Vec<Encoding> = (0..25).map(|index| vec![f64::from(index)]).collect();
        let added: Vec<Encoding> = (25..35).map(|index| vec![f64::from(index)]).collect();
        let merged = merge(existing, added);
        assert_eq!(merged.len(), MAX_MODEL_SAMPLES);
        assert_eq!(merged[0], vec![5.0]);
        assert_eq!(merged[29], vec![34.0]);
        assert_eq!(merge(vec![vec![1.0]], vec![vec![2.0]]).len(), 2);
    }

    #[test]
    fn pick_evenly_truncates_like_python_int() {
        let samples: Vec<usize> = (0..25).collect();
        // step = 25 / 10 = 2.5 and int(i * step) for i in range(10).
        assert_eq!(
            pick_evenly(&samples, 10),
            [0, 2, 5, 7, 10, 12, 15, 17, 20, 22]
        );
        assert_eq!(pick_evenly(&samples[..4], 10), [0, 1, 2, 3]);
        assert_eq!(
            pick_evenly(&samples[..13], 10),
            [0, 1, 2, 3, 5, 6, 7, 9, 10, 11]
        );
        assert!(pick_evenly::<usize>(&[], 10).is_empty());
    }
}
