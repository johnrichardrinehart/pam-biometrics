//! Face scans and enrollment from camera frames.

use std::time::Duration;

use pam_biometrics_face::{Engine, Frame, distance};

use crate::camera::Camera;
use crate::model::{Encoding, pick_evenly};

/// Enrollment needs exactly one face in at least this many frames.
pub const MIN_ENROLL_SAMPLES: usize = 3;

/// Enrollment stores at most this many samples per run.
pub const MAX_ENROLL_SAMPLES: usize = 10;

/// The result of a scan.
#[derive(Clone, Debug, PartialEq)]
pub struct Scan {
    /// The smallest distance between a face and the model.
    pub best: Option<f64>,
    /// The number of frames with at least one face.
    pub faces: u32,
}

/// Reads faces from a source of frames.
pub trait Scanner: Send + 'static {
    /// Compares the faces in the frames with `model`. Stops at the first
    /// frame with a distance at or below `stop_at`.
    fn scan(&mut self, model: &[Encoding], stop_at: f64) -> Result<Scan, String>;

    /// Returns encodings from frames with exactly one face.
    fn enroll(&mut self) -> Result<Vec<Encoding>, String>;
}

/// A [`Scanner`] that reads a V4L2 camera and encodes faces with dlib.
#[derive(Debug)]
pub struct CameraScanner {
    /// The camera.
    pub camera: Camera,
    /// The face engine.
    pub engine: Engine,
    /// The duration of a scan.
    pub scan_duration: Duration,
    /// The duration of an enrollment.
    pub enroll_duration: Duration,
    /// Frames with a lower mean brightness (0 to 255) have no usable face.
    pub dark_threshold: f64,
}

impl CameraScanner {
    /// Calls `visit` with the faces of each frame that is bright enough.
    /// `visit` returns false to stop the capture. Returns the number of
    /// frames that were too dark.
    fn each_frame(
        &mut self,
        duration: Duration,
        mut visit: impl FnMut(Vec<pam_biometrics_face::Face>) -> bool,
    ) -> Result<usize, String> {
        let mut capture = self
            .camera
            .capture(duration)
            .map_err(|error| format!("cannot start ffmpeg: {error}"))?;
        let mut dark = 0;
        while let Some(rgb) = capture.next_frame() {
            let frame = Frame {
                rgb,
                width: self.camera.width,
                height: self.camera.height,
            };
            if frame.brightness() < self.dark_threshold {
                dark += 1;
                continue;
            }
            let faces = self
                .engine
                .faces(&frame)
                .map_err(|error| error.to_string())?;
            if !visit(faces) {
                break;
            }
        }
        Ok(dark)
    }
}

impl Scanner for CameraScanner {
    fn scan(&mut self, model: &[Encoding], stop_at: f64) -> Result<Scan, String> {
        let mut scan = Scan {
            best: None,
            faces: 0,
        };
        self.each_frame(self.scan_duration, |faces| {
            let Some(closest) = faces
                .iter()
                .flat_map(|face| model.iter().map(|sample| distance(&face.encoding, sample)))
                .reduce(f64::min)
            else {
                return true;
            };
            scan.faces += 1;
            scan.best = Some(scan.best.map_or(closest, |best| best.min(closest)));
            closest > stop_at
        })?;
        Ok(scan)
    }

    fn enroll(&mut self) -> Result<Vec<Encoding>, String> {
        let mut samples = Vec::new();
        let (mut no_face, mut several) = (0, 0);
        let dark = self.each_frame(self.enroll_duration, |mut faces| {
            match faces.len() {
                0 => no_face += 1,
                1 => samples.push(faces.remove(0).encoding),
                _ => several += 1,
            }
            true
        })?;
        if samples.len() < MIN_ENROLL_SAMPLES {
            let frames = dark + no_face + several + samples.len();
            if frames == 0 {
                return Err(format!(
                    "the camera gave no frames in {:.0} s",
                    self.enroll_duration.as_secs_f64()
                ));
            }
            return Err(format!(
                "{} of {frames} frames had exactly one face, enrollment needs \
                 {MIN_ENROLL_SAMPLES}: {dark} too dark (mean brightness below {}), \
                 {no_face} without a face, {several} with more than one face",
                samples.len(),
                self.dark_threshold
            ));
        }
        Ok(pick_evenly(&samples, MAX_ENROLL_SAMPLES))
    }
}
