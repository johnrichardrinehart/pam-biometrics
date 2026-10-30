//! pam-biometricsd: the camera daemon of pam-biometrics.
//!
//! The daemon owns the camera and the face models. Clients connect to its
//! Unix socket. The daemon identifies each client from the peer credentials.

mod camera;
mod model;
mod scanner;
mod service;

use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::sys::stat::{Mode, umask};
use pam_biometrics_face::{Engine, Frame};
use pam_biometrics_policy::DEFAULT_POLICY_PATH;
use pam_biometrics_protocol::{DEFAULT_SOCKET, MAX_REQUEST_BYTES, Reply, Request};

use crate::camera::Camera;
use crate::scanner::{CameraScanner, Scanner};
use crate::service::{Config, Service, SystemUsers, UserDb as _};

/// A connection that sends no request in this time is closed.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// `wait` and `take` wait at most the scan time plus this margin.
const SETTLE_MARGIN: Duration = Duration::from_secs(10);

/// The model directory that the build sets.
const DEFAULT_MODEL_DIR: &str = match option_env!("PAM_BIOMETRICS_MODEL_DIR") {
    Some(directory) => directory,
    None => "/usr/share/pam-biometrics/models",
};

/// Camera daemon for the pam-biometrics face factor.
#[derive(Debug, Parser)]
#[command(
    version,
    subcommand_negates_reqs = true,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(flatten)]
    daemon: DaemonArgs,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Args)]
struct DaemonArgs {
    /// V4L2 camera device.
    #[arg(long, required = true)]
    device: Option<String>,

    /// V4L2 input format, for example mjpeg.
    #[arg(long)]
    input_format: Option<String>,

    /// Frame width in pixels.
    #[arg(long, default_value_t = 640)]
    width: usize,

    /// Frame height in pixels.
    #[arg(long, default_value_t = 360)]
    height: usize,

    /// Duration of a scan in seconds.
    #[arg(long, default_value_t = 4.0)]
    scan_seconds: f64,

    /// Duration of an enrollment in seconds.
    #[arg(long, default_value_t = 6.0)]
    enroll_seconds: f64,

    /// Time in seconds after which a scan result expires.
    #[arg(long, default_value_t = 120.0)]
    result_ttl: f64,

    /// Frames with a lower mean brightness, from 0 to 255, are skipped.
    #[arg(long, default_value_t = 10.0)]
    dark_threshold: f64,

    /// This user can start scans for any user.
    #[arg(long)]
    greeter_user: Option<String>,

    /// Directory of the face models.
    #[arg(long, required = true)]
    state_dir: Option<PathBuf>,

    /// Policy file. Scans stop at its strictest match distance for the user.
    #[arg(long, default_value = DEFAULT_POLICY_PATH)]
    policy: PathBuf,

    /// Socket path.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    /// Directory of the dlib model files.
    #[arg(long, default_value = DEFAULT_MODEL_DIR)]
    model_dir: PathBuf,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the faces and encodings of a raw RGB24 image as JSON.
    Encode {
        /// Image width in pixels.
        #[arg(long)]
        width: usize,

        /// Image height in pixels.
        #[arg(long)]
        height: usize,

        /// Directory of the dlib model files.
        #[arg(long, default_value = DEFAULT_MODEL_DIR)]
        model_dir: PathBuf,

        /// File with width × height × 3 bytes.
        file: PathBuf,
    },
}

fn seconds(value: f64, name: &str) -> Result<Duration, String> {
    Duration::try_from_secs_f64(value)
        .map_err(|_| format!("--{name} must be a non-negative number"))
}

fn encode(width: usize, height: usize, model_dir: &Path, file: &Path) -> Result<(), String> {
    let rgb = fs::read(file).map_err(|error| format!("{}: {error}", file.display()))?;
    let mut engine = Engine::load(model_dir).map_err(|error| error.to_string())?;
    let faces = engine
        .faces(&Frame {
            rgb: &rgb,
            width,
            height,
        })
        .map_err(|error| error.to_string())?;
    let faces: Vec<serde_json::Value> = faces
        .into_iter()
        .map(|face| serde_json::json!({ "location": face.location, "encoding": face.encoding }))
        .collect();
    println!("{}", serde_json::Value::Array(faces));
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> nix::Result<u32> {
    getsockopt(stream, PeerCredentials).map(|credentials| credentials.uid())
}

fn serve_connection<S: Scanner>(service: &Arc<Service<S>>, stream: &UnixStream) {
    let Ok(uid) = peer_uid(stream) else {
        return;
    };
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let mut line = String::new();
    let reply = match BufReader::new(stream.take(MAX_REQUEST_BYTES)).read_line(&mut line) {
        Ok(_) => match serde_json::from_str::<Request>(&line) {
            Ok(request) => service.handle(uid, &request),
            Err(_) => Reply::error("bad request"),
        },
        Err(_) => return,
    };
    let Ok(mut text) = serde_json::to_vec(&reply) else {
        return;
    };
    text.push(b'\n');
    let mut stream = stream;
    let _ = stream.write_all(&text);
}

fn run(args: DaemonArgs) -> Result<(), String> {
    let device = args.device.expect("clap requires --device");
    let state_dir = args.state_dir.expect("clap requires --state-dir");
    let scan_duration = seconds(args.scan_seconds, "scan-seconds")?;
    let greeter_uid = match &args.greeter_user {
        None => None,
        Some(name) => Some(
            SystemUsers
                .lookup(name)
                .ok_or_else(|| format!("unknown greeter user {name}"))?
                .1,
        ),
    };
    let config = Config {
        state_dir,
        device: device.clone(),
        policy: args.policy,
        result_ttl: seconds(args.result_ttl, "result-ttl")?,
        settle_limit: scan_duration + SETTLE_MARGIN,
        greeter_uid,
    };
    let engine = Engine::load(&args.model_dir).map_err(|error| error.to_string())?;
    let scanner = CameraScanner {
        camera: Camera {
            device,
            input_format: args.input_format,
            width: args.width,
            height: args.height,
        },
        engine,
        scan_duration,
        enroll_duration: seconds(args.enroll_seconds, "enroll-seconds")?,
        dark_threshold: args.dark_threshold,
    };

    // Model files are private to the daemon.
    umask(Mode::from_bits_truncate(0o077));
    match fs::remove_file(&args.socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{}: {error}", args.socket.display())),
    }
    let listener = UnixListener::bind(&args.socket)
        .map_err(|error| format!("{}: {error}", args.socket.display()))?;
    // Every user must reach the socket: the greeter, PAM in a screen locker,
    // and key bindings. The handlers check the peer credentials.
    fs::set_permissions(&args.socket, fs::Permissions::from_mode(0o666))
        .map_err(|error| format!("{}: {error}", args.socket.display()))?;

    let service = Service::new(config, Box::new(SystemUsers), scanner);
    eprintln!("listening on {}", args.socket.display());
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let service = Arc::clone(&service);
                thread::spawn(move || serve_connection(&service, &stream));
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Encode {
            width,
            height,
            model_dir,
            file,
        }) => encode(width, height, &model_dir, &file),
        None => run(cli.daemon),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pam-biometricsd: {error}");
            ExitCode::FAILURE
        }
    }
}
