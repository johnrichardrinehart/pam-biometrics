//! Socket protocol between `pam-biometricsd` and its clients.
//!
//! A client connects to the Unix socket, writes one request as a line of
//! JSON, and reads one reply as a line of JSON. The daemon identifies the
//! client from the peer credentials of the socket.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The default socket path.
pub const DEFAULT_SOCKET: &str = "/run/pam-biometrics/socket";

/// The maximum length of a request line, newline included.
pub const MAX_REQUEST_BYTES: u64 = 4096;

/// A request operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Start a background scan. The result stays until a `take` or the TTL.
    Scan,
    /// Return the stored result. Do not consume it.
    Status,
    /// Wait for a running scan, then return the stored result.
    Wait,
    /// Wait for a running scan, then return and consume the stored result.
    Take,
    /// Scan now and return the result. Do not store it.
    Verify,
    /// Record face samples for the user.
    Enroll,
    /// Remove the face samples of the user.
    Delete,
    /// Count the face samples of the user.
    List,
}

impl Op {
    /// Returns the name that the protocol uses.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Status => "status",
            Self::Wait => "wait",
            Self::Take => "take",
            Self::Verify => "verify",
            Self::Enroll => "enroll",
            Self::Delete => "delete",
            Self::List => "list",
        }
    }
}

/// A request from a client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The operation.
    pub op: Op,
    /// The user that the operation applies to.
    pub user: String,
    /// For `enroll`: keep the samples that exist and add new ones.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub add: bool,
    /// For `wait` and `take`: the maximum time to wait for a running scan.
    /// The daemon also applies its own limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
}

impl Request {
    /// Creates a request without options.
    #[must_use]
    pub fn new(op: Op, user: &str) -> Self {
        Self {
            op,
            user: user.to_owned(),
            add: false,
            wait_ms: None,
        }
    }
}

/// The state of the last scan of a user.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ScanResult {
    /// A scan runs.
    Scanning,
    /// A scan ended.
    Finished {
        /// The smallest distance between a face and the enrolled samples.
        /// `None` if no frame had a face.
        best: Option<f64>,
        /// The number of frames with at least one face.
        faces: u32,
    },
    /// The user has no enrolled face.
    NoModel,
}

/// A reply from the daemon. Each operation sets a subset of the fields.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    /// The reason for a failure. The other fields are absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The camera device of the daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// For `scan`: true if this request started a scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<bool>,
    /// For `status`, `wait`, `take`, and `verify`: the scan state. Absent if
    /// the daemon has no result for the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ScanResult>,
    /// For `enroll` and `list`: the number of enrolled samples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub samples: Option<usize>,
    /// For `delete`: true if a model existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
}

impl Reply {
    /// Creates an error reply.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            error: Some(message.into()),
            ..Self::default()
        }
    }
}

/// Sends `request` to the daemon at `socket` and reads the reply. `timeout`
/// limits each read and write.
pub fn call(socket: &Path, request: &Request, timeout: Duration) -> io::Result<Reply> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut line = serde_json::to_vec(request).map_err(io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    if reply.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the daemon closed the connection",
        ));
    }
    serde_json::from_str(&reply).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_format() {
        let mut request = Request::new(Op::Enroll, "alice");
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"op":"enroll","user":"alice"}"#
        );
        request.add = true;
        request.wait_ms = Some(500);
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"op":"enroll","user":"alice","add":true,"wait_ms":500}"#
        );
        assert!(serde_json::from_str::<Request>(r#"{"op":"scan","user":"a","x":1}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"op":"verdict","user":"a"}"#).is_err());
    }

    #[test]
    fn reply_wire_format() {
        let reply = Reply {
            device: Some("/dev/video0".to_owned()),
            result: Some(ScanResult::Finished {
                best: Some(0.25),
                faces: 4,
            }),
            ..Reply::default()
        };
        let text = serde_json::to_string(&reply).unwrap();
        assert_eq!(
            text,
            r#"{"device":"/dev/video0","result":{"state":"finished","best":0.25,"faces":4}}"#
        );
        assert_eq!(serde_json::from_str::<Reply>(&text).unwrap(), reply);

        let no_face = ScanResult::Finished {
            best: None,
            faces: 0,
        };
        assert_eq!(
            serde_json::to_string(&no_face).unwrap(),
            r#"{"state":"finished","best":null,"faces":0}"#
        );
        assert_eq!(
            serde_json::to_string(&ScanResult::NoModel).unwrap(),
            r#"{"state":"no-model"}"#
        );
        assert_eq!(
            serde_json::to_string(&Reply::error("permission denied")).unwrap(),
            r#"{"error":"permission denied"}"#
        );
    }

    #[test]
    fn call_round_trip() {
        let directory =
            std::env::temp_dir().join(format!("pam-biometrics-protocol-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let socket = directory.join("socket");
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let request: Request = serde_json::from_str(&line).unwrap();
            let mut reply = serde_json::to_vec(&Reply {
                samples: Some(request.user.len()),
                ..Reply::default()
            })
            .unwrap();
            reply.push(b'\n');
            (&stream).write_all(&reply).unwrap();
        });
        let reply = call(
            &socket,
            &Request::new(Op::List, "alice"),
            Duration::from_secs(5),
        )
        .unwrap();
        server.join().unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        assert_eq!(reply.samples, Some(5));
    }
}
