//! RGB frames from a V4L2 device through an ffmpeg subprocess.

use std::io::{self, Read as _};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// The time that ffmpeg gets after the capture duration before the watchdog
/// kills it.
const WATCHDOG_GRACE: Duration = Duration::from_secs(5);

/// A V4L2 camera.
#[derive(Clone, Debug)]
pub struct Camera {
    /// The device path.
    pub device: String,
    /// The V4L2 input format, for example `mjpeg`.
    pub input_format: Option<String>,
    /// The frame width in pixels.
    pub width: usize,
    /// The frame height in pixels.
    pub height: usize,
}

impl Camera {
    /// Returns the ffmpeg arguments that capture from the device.
    fn arguments(&self) -> Vec<String> {
        let mut arguments: Vec<String> = [
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "v4l2",
        ]
        .map(str::to_owned)
        .into();
        if let Some(format) = &self.input_format {
            arguments.extend([
                "-input_format".to_owned(),
                format.clone(),
                "-video_size".to_owned(),
                format!("{}x{}", self.width, self.height),
            ]);
        }
        arguments.extend([
            "-i".to_owned(),
            self.device.clone(),
            "-vf".to_owned(),
            format!("scale={}:{}", self.width, self.height),
            "-pix_fmt".to_owned(),
            "rgb24".to_owned(),
            "-f".to_owned(),
            "rawvideo".to_owned(),
            "pipe:1".to_owned(),
        ]);
        arguments
    }

    /// Starts a capture that delivers frames for `duration`.
    pub fn capture(&self, duration: Duration) -> io::Result<Capture> {
        let mut child = Command::new("ffmpeg")
            .args(self.arguments())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let pid = Pid::from_raw(i32::try_from(child.id()).expect("PIDs fit in i32"));
        // A stalled device blocks read(). The watchdog kills ffmpeg so that
        // read() returns.
        let (stop, stopped) = mpsc::channel::<()>();
        let watchdog = thread::spawn(move || {
            if stopped.recv_timeout(duration + WATCHDOG_GRACE) == Err(RecvTimeoutError::Timeout) {
                let _ = kill(pid, Signal::SIGKILL);
            }
        });
        Ok(Capture {
            child,
            stdout,
            deadline: Instant::now() + duration,
            frame: vec![0; self.width * self.height * 3],
            watchdog: Some((stop, watchdog)),
        })
    }
}

/// A running capture. Dropping it stops ffmpeg.
#[derive(Debug)]
pub struct Capture {
    child: Child,
    stdout: ChildStdout,
    deadline: Instant,
    frame: Vec<u8>,
    watchdog: Option<(mpsc::Sender<()>, JoinHandle<()>)>,
}

impl Capture {
    /// Reads the next frame. Returns `None` after the capture duration or
    /// at the end of the stream.
    pub fn next_frame(&mut self) -> Option<&[u8]> {
        if Instant::now() >= self.deadline {
            return None;
        }
        match self.stdout.read_exact(&mut self.frame) {
            Ok(()) => Some(&self.frame),
            Err(_) => None,
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // Stop the watchdog first, so that it cannot signal a reused PID.
        if let Some((stop, watchdog)) = self.watchdog.take() {
            drop(stop);
            let _ = watchdog.join();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffmpeg_arguments() {
        let mut camera = Camera {
            device: "/dev/video0".to_owned(),
            input_format: None,
            width: 640,
            height: 360,
        };
        assert_eq!(
            camera.arguments().join(" "),
            "-nostdin -hide_banner -loglevel error -f v4l2 -i /dev/video0 -vf scale=640:360 -pix_fmt rgb24 -f rawvideo pipe:1"
        );
        camera.input_format = Some("mjpeg".to_owned());
        assert_eq!(
            camera.arguments().join(" "),
            "-nostdin -hide_banner -loglevel error -f v4l2 -input_format mjpeg -video_size 640x360 -i /dev/video0 -vf scale=640:360 -pix_fmt rgb24 -f rawvideo pipe:1"
        );
    }
}
