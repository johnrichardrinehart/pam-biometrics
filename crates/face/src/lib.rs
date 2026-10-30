//! Face detection and encoding through dlib.
//!
//! The engine uses the same steps and parameters as the defaults of the
//! `face_recognition` Python package: the HOG frontal face detector without
//! upsampling, the 5-point shape predictor, 150 pixel face chips, one jitter,
//! and the ResNet model `dlib_face_recognition_resnet_model_v1.dat`.
//! Encodings from this crate and from `face_recognition` are therefore
//! comparable with the Euclidean distance.

use std::path::Path;

/// The file name of the 5-point shape predictor.
pub const SHAPE_PREDICTOR_FILE: &str = "shape_predictor_5_face_landmarks.dat";

/// The file name of the face recognition network.
pub const RECOGNITION_MODEL_FILE: &str = "dlib_face_recognition_resnet_model_v1.dat";

/// The number of values in an encoding.
pub const ENCODING_LENGTH: usize = 128;

#[allow(
    unused_qualifications,
    reason = "the cxx bridge expansion qualifies paths"
)]
#[cxx::bridge(namespace = "pam_biometrics")]
mod ffi {
    /// A face box in (top, right, bottom, left) order, as `face_recognition`
    /// reports it, and the encoding of the face.
    struct Face {
        top: i64,
        right: i64,
        bottom: i64,
        left: i64,
        encoding: Vec<f32>,
    }

    unsafe extern "C++" {
        include!("pam-biometrics-face/src/engine.h");

        type Engine;

        fn new_engine(shape_predictor: &str, recognition_model: &str) -> Result<UniquePtr<Engine>>;

        fn analyze(
            engine: Pin<&mut Engine>,
            rgb: &[u8],
            width: usize,
            height: usize,
        ) -> Result<Vec<Face>>;
    }
}

// SAFETY: The C++ engine holds no thread-local state. `Engine` takes it by
// `&mut self`, so one thread at a time uses it.
unsafe impl Send for ffi::Engine {}

/// An error from dlib.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

/// A frame of 8-bit RGB pixels in row order.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    /// The pixels, three bytes each.
    pub rgb: &'a [u8],
    /// Pixels per row.
    pub width: usize,
    /// Rows.
    pub height: usize,
}

impl Frame<'_> {
    /// Returns the mean of all color values, from 0 to 255.
    #[must_use]
    pub fn brightness(&self) -> f64 {
        if self.rgb.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.rgb.iter().map(|value| u64::from(*value)).sum();
        #[expect(
            clippy::cast_precision_loss,
            reason = "a frame has far fewer than 2^52 bytes"
        )]
        let mean = sum as f64 / self.rgb.len() as f64;
        mean
    }
}

/// A face that the detector found.
#[derive(Clone, Debug, PartialEq)]
pub struct Face {
    /// The face box in (top, right, bottom, left) order.
    pub location: [i64; 4],
    /// The 128 values of the encoding.
    pub encoding: Vec<f64>,
}

/// The dlib detector, shape predictor, and network.
pub struct Engine {
    inner: cxx::UniquePtr<ffi::Engine>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

impl Engine {
    /// Loads [`SHAPE_PREDICTOR_FILE`] and [`RECOGNITION_MODEL_FILE`] from
    /// `model_dir`.
    pub fn load(model_dir: &Path) -> Result<Self, Error> {
        let path = |name: &str| {
            let path = model_dir.join(name);
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| Error(format!("{} is not valid UTF-8", path.display())))
        };
        let inner = ffi::new_engine(&path(SHAPE_PREDICTOR_FILE)?, &path(RECOGNITION_MODEL_FILE)?)
            .map_err(|error| {
            Error(format!(
                "cannot load the models from {}: {error}",
                model_dir.display()
            ))
        })?;
        Ok(Self { inner })
    }

    /// Finds the faces in `frame` and encodes each face.
    pub fn faces(&mut self, frame: &Frame<'_>) -> Result<Vec<Face>, Error> {
        let faces = ffi::analyze(self.inner.pin_mut(), frame.rgb, frame.width, frame.height)
            .map_err(|error| Error(error.what().to_owned()))?;
        Ok(faces
            .into_iter()
            .map(|face| Face {
                location: [face.top, face.right, face.bottom, face.left],
                encoding: face.encoding.into_iter().map(f64::from).collect(),
            })
            .collect())
    }
}

/// Returns the Euclidean distance between two encodings.
#[must_use]
pub fn distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(a, b)| (a - b) * (a - b))
        .sum::<f64>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_is_euclidean() {
        assert!((distance(&[0.0, 3.0], &[4.0, 0.0]) - 5.0).abs() < 1e-12);
        assert!(distance(&[0.5; 128], &[0.5; 128]).abs() < f64::EPSILON);
    }

    #[test]
    fn brightness_is_the_mean() {
        let rgb = [0, 0, 0, 30, 30, 30];
        let frame = Frame {
            rgb: &rgb,
            width: 2,
            height: 1,
        };
        assert!((frame.brightness() - 15.0).abs() < f64::EPSILON);
        let empty = Frame {
            rgb: &[],
            width: 0,
            height: 0,
        };
        assert!(empty.brightness().abs() < f64::EPSILON);
    }

    #[test]
    fn missing_models_are_an_error() {
        let error = Engine::load(Path::new("/nonexistent")).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("cannot load the models from /nonexistent")
        );
    }
}
