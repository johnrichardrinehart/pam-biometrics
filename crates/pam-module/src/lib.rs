//! `pam_biometrics.so`: the pam-biometrics steps around the password module.
//!
//! Usage:
//!
//! ```text
//! auth [success=ok ignore=ignore default=die] pam_biometrics.so start [ARGS...]
//! auth requisite pam_unix.so nullok try_first_pass
//! auth [success=ok ignore=ignore default=die] pam_biometrics.so finish [ARGS...]
//! ```
//!
//! The first argument selects the mode. Without `start` or `finish` as the
//! first argument, the module runs `finish`. The module passes the other
//! arguments to the helper.
//!
//! `start` runs `pam-biometrics pam-session ARGS...` from a path that the
//! build sets. The environment of the helper contains only `PAM_USER`,
//! `PAM_SERVICE`, and `PAM_TYPE=auth`. The helper runs the enabled factors
//! until `finish` or `pam_end`. `start` then asks for the password. The
//! face trigger as a response starts a face scan and asks again. Any other
//! response becomes `PAM_AUTHTOK` for the password module, and `start`
//! returns `PAM_IGNORE`. Without an enabled factor, `start` asks nothing
//! and returns `PAM_IGNORE`.
//!
//! `finish` uses the session of `start`, or starts one. It shows the lines
//! of the helper as information messages while the helper waits for a
//! decision, and maps the exit code of the helper to the result:
//!
//! | Exit status | Meaning             | Result         |
//! |-------------|---------------------|----------------|
//! | 0           | A match.            | `PAM_SUCCESS`  |
//! | 10          | A reject.           | `PAM_AUTH_ERR` |
//! | other       | No decision.        | `PAM_IGNORE`   |
//!
//! With the policy value `after_password: prompt`, the helper asks for one
//! prompt before the wait. The face trigger as the response starts a face
//! scan. A conversation error gives `PAM_CONV_ERR`.
//!
//! With `after_password: wait`, `finish` asks nothing. During the wait it
//! reads lines from `PAM_TTY` if it is a terminal in line mode (`ICANON`),
//! for example under `login`, `sudo`, or `su`. A line equal to the face
//! trigger starts a face scan. Other lines are discarded. The module opens
//! the terminal read-only and non-blocking, never changes its settings,
//! never reads it outside the wait or without `ICANON`, and closes it
//! before `finish` returns. Nothing read from the terminal is used as a
//! secret: a line only selects whether to scan.
//!
//! A crash of the helper or of this module gives no decision, so that a
//! fault cannot lock the user out. The password stays necessary in the rest
//! of the stack. `pam_end` stops a helper that still runs.
//!
//! The module and the helper talk in lines over a socket pair on the
//! standard input and output of the helper. The protocol is in the
//! documentation of the `pam-biometrics` helper module. The password never
//! goes to the helper.

use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_void};
use std::io::{self, Read as _};
use std::net::Shutdown;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// The helper program. The Nix build sets the store path.
const HELPER: &str = match option_env!("PAM_BIOMETRICS_HELPER") {
    Some(path) => path,
    None => "/usr/bin/pam-biometrics",
};

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_CONV_ERR: c_int = 19;
const PAM_IGNORE: c_int = 25;
const PAM_SERVICE: c_int = 1;
const PAM_TTY: c_int = 3;
const PAM_AUTHTOK: c_int = 6;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_TEXT_INFO: c_int = 4;
const PAM_DATA_SILENT: c_int = 0x4000_0000;
const LOG_ERR: c_int = 3;
const LOG_WARNING: c_int = 4;

const HELPER_MATCH: i32 = 0;
const HELPER_REJECT: i32 = 10;

/// The name of the session in the PAM handle.
const DATA_NAME: &CStr = c"pam_biometrics_session";

/// The time that the helper gets to answer a `scan` request. The daemon
/// call of the helper times out after 5 s.
const SCAN_REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// The trigger starts at most this many scans in `start`. After that, every
/// response is the password. An application that repeats a response
/// without the user cannot start scans forever.
const MAX_TRIGGERS: u32 = 5;

/// The time that the helper gets for its first lines.
const GREETING_TIMEOUT: Duration = Duration::from_secs(10);

/// The time that the helper gets to release the devices after `stop`.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// The time between SIGTERM and SIGKILL.
const TERM_GRACE: Duration = Duration::from_millis(500);

/// The longest line from the helper.
const MAX_LINE: usize = 64 * 1024;

/// The longest line from the terminal that `finish` keeps.
const MAX_TTY_LINE: usize = 4096;

/// Returns a pollfd that waits for input on `fd`.
const fn pollfd(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Waits up to `timeout` milliseconds, or without a limit for -1, for one of
/// `descriptors`. Returns the number of ready descriptors. Repeats after a
/// signal.
fn poll(descriptors: &mut [libc::pollfd], timeout: c_int) -> io::Result<usize> {
    let count = libc::nfds_t::try_from(descriptors.len()).unwrap_or(libc::nfds_t::MAX);
    loop {
        // SAFETY: `descriptors` holds `count` valid pollfd structures.
        let ready = unsafe { libc::poll(descriptors.as_mut_ptr(), count, timeout) };
        if let Ok(ready) = usize::try_from(ready) {
            return Ok(ready);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// The opaque `pam_handle_t`.
#[repr(C)]
#[derive(Debug)]
pub struct PamHandle {
    _private: [u8; 0],
}

type Cleanup = unsafe extern "C" fn(pamh: *mut PamHandle, data: *mut c_void, error_status: c_int);

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
    fn pam_set_data(
        pamh: *mut PamHandle,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<Cleanup>,
    ) -> c_int;
    fn pam_prompt(
        pamh: *mut PamHandle,
        style: c_int,
        response: *mut *mut c_char,
        fmt: *const c_char,
        ...
    ) -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

/// Maps the exit code of the helper to a PAM result. `None` stands for a
/// termination by a signal.
const fn pam_result(code: Option<i32>) -> c_int {
    match code {
        Some(HELPER_MATCH) => PAM_SUCCESS,
        Some(HELPER_REJECT) => PAM_AUTH_ERR,
        _ => PAM_IGNORE,
    }
}

/// The step that the module runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Before the password module.
    Start,
    /// After the password module.
    Finish,
}

/// Splits the module arguments into the mode and the helper arguments.
fn mode<'a>(arguments: &'a [&'a OsStr]) -> (Mode, &'a [&'a OsStr]) {
    match arguments.split_first() {
        Some((first, rest)) if first.as_bytes() == b"start" => (Mode::Start, rest),
        Some((first, rest)) if first.as_bytes() == b"finish" => (Mode::Finish, rest),
        _ => (Mode::Finish, arguments),
    }
}

/// Converts the module arguments.
///
/// # Safety
///
/// `argv` must point to `argc` valid C strings, or `argc` must be 0.
unsafe fn arguments<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a OsStr> {
    let count = usize::try_from(argc).unwrap_or(0);
    if count == 0 || argv.is_null() {
        return Vec::new();
    }
    // SAFETY: The caller guarantees `count` valid pointers.
    let pointers = unsafe { std::slice::from_raw_parts(argv, count) };
    pointers
        .iter()
        .filter(|pointer| !pointer.is_null())
        // SAFETY: Each pointer is a valid C string.
        .map(|pointer| OsStr::from_bytes(unsafe { CStr::from_ptr(*pointer) }.to_bytes()))
        .collect()
}

fn log(pamh: *mut PamHandle, priority: c_int, message: &str) {
    if pamh.is_null() {
        return;
    }
    if let Ok(message) = CString::new(message) {
        // SAFETY: `pamh` is the handle of this call. The format consumes one
        // C string.
        unsafe { pam_syslog(pamh, priority, c"%s".as_ptr(), message.as_ptr()) };
    }
}

/// A response from the application. Zeroes and frees the text on drop.
struct Secret(*mut c_char);

impl Secret {
    fn bytes(&self) -> &[u8] {
        // SAFETY: The pointer is a valid C string that this value owns.
        unsafe { CStr::from_ptr(self.0) }.to_bytes()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: The pointer is a valid C string from malloc that this
        // value owns. The volatile writes keep the compiler from removing
        // the zeroes before free.
        unsafe {
            let length = libc::strlen(self.0);
            for index in 0..length {
                std::ptr::write_volatile(self.0.add(index), 0);
            }
            libc::free(self.0.cast());
        }
    }
}

/// The conversation with the user and the PAM items.
trait Conversation {
    /// Shows an information message.
    fn info(&mut self, text: &[u8]);
    /// Asks a question without echo. Returns `None` if the application
    /// gives no response.
    fn ask(&mut self, prompt: &CStr) -> Option<Secret>;
    /// Sets `PAM_AUTHTOK`. On an error, the password module asks itself.
    fn set_password(&mut self, password: &Secret);
}

/// The conversation through the PAM handle.
struct Pam(*mut PamHandle);

impl Conversation for Pam {
    fn info(&mut self, text: &[u8]) {
        if let Ok(text) = CString::new(text) {
            // SAFETY: The handle is valid for this call. The format consumes
            // one C string. PAM_TEXT_INFO needs no response.
            unsafe {
                pam_prompt(
                    self.0,
                    PAM_TEXT_INFO,
                    std::ptr::null_mut(),
                    c"%s".as_ptr(),
                    text.as_ptr(),
                )
            };
        }
    }

    fn ask(&mut self, prompt: &CStr) -> Option<Secret> {
        let mut response: *mut c_char = std::ptr::null_mut();
        // SAFETY: The handle is valid for this call. The format consumes one
        // C string. The response is a string from malloc or null.
        let result = unsafe {
            pam_prompt(
                self.0,
                PAM_PROMPT_ECHO_OFF,
                &raw mut response,
                c"%s".as_ptr(),
                prompt.as_ptr(),
            )
        };
        let secret = (!response.is_null()).then_some(Secret(response));
        if result == PAM_SUCCESS { secret } else { None }
    }

    fn set_password(&mut self, password: &Secret) {
        // SAFETY: The handle is valid. PAM copies the string.
        if unsafe { pam_set_item(self.0, PAM_AUTHTOK, password.0.cast()) } != PAM_SUCCESS {
            log(self.0, LOG_ERR, "cannot set PAM_AUTHTOK");
        }
    }
}

/// A line from the helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Message<'a> {
    Off,
    Prompt(&'a [u8]),
    Reprompt(&'a [u8]),
    Trigger(&'a [u8]),
    AfterPasswordPrompt,
    Ready,
    Info(&'a [u8]),
    Ask(&'a [u8]),
    /// The reply to `scan`.
    ScanReply,
    Unknown,
}

impl<'a> Message<'a> {
    fn parse(line: &'a [u8]) -> Self {
        let (word, text) = match line.iter().position(|byte| *byte == b' ') {
            Some(space) => (&line[..space], &line[space + 1..]),
            None => (line, &line[line.len()..]),
        };
        match word {
            b"off" => Self::Off,
            b"prompt" => Self::Prompt(text),
            b"reprompt" => Self::Reprompt(text),
            b"trigger" => Self::Trigger(text),
            b"after-password" if text == b"prompt" => Self::AfterPasswordPrompt,
            b"ready" => Self::Ready,
            b"info" => Self::Info(text),
            b"ask" => Self::Ask(text),
            b"scan" => Self::ScanReply,
            _ => Self::Unknown,
        }
    }
}

/// How [`Session::finish`] ended.
#[derive(Debug)]
enum Finished {
    /// The helper exited, or waitpid failed.
    Exited(io::Result<ExitStatus>),
    /// The application gave no response to the prompt of `finish`.
    ConversationError,
}

/// Returns the device of a `PAM_TTY` value: `/dev/NAME` for a relative name
/// such as `tty1` or `pts/3`, or the value itself if it is under `/dev/`.
/// Returns `None` for an X display such as `:0` and for other paths.
fn tty_path(item: &[u8]) -> Option<PathBuf> {
    if item.is_empty() || item.contains(&b':') {
        return None;
    }
    let path = if item.starts_with(b"/dev/") {
        item.to_vec()
    } else if item.starts_with(b"/") {
        return None;
    } else {
        [b"/dev/", item].concat()
    };
    if path.split(|byte| *byte == b'/').any(|part| part == b"..") {
        return None;
    }
    Some(PathBuf::from(OsStr::from_bytes(&path)))
}

/// Removes the complete lines from `pending` and returns them without the
/// line end. Drops a partial line that grows beyond [`MAX_TTY_LINE`].
fn take_lines(pending: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
        let mut line: Vec<u8> = pending.drain(..=end).collect();
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        lines.push(line);
    }
    if pending.len() > MAX_TTY_LINE {
        pending.clear();
    }
    lines
}

/// The terminal of the application in line mode. `finish` reads trigger
/// lines from it during the wait. Dropping it closes the descriptor.
#[derive(Debug)]
struct Tty {
    fd: OwnedFd,
    pending: Vec<u8>,
}

impl Tty {
    /// Opens `path` read-only and non-blocking. Returns `None` unless it is
    /// a character device with a terminal in line mode. Discards the input
    /// that waits already, so that only lines from the wait count.
    fn open(path: &Path) -> Option<Self> {
        let path = CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: `path` is a C string. The flags open no controlling
        // terminal and do not block.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }
        // SAFETY: `open` returned a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `status` has room for a stat structure.
        if unsafe { libc::fstat(fd.as_raw_fd(), status.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: `fstat` filled the structure.
        if unsafe { status.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFCHR {
            return None;
        }
        let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `termios` has room for a termios structure.
        if unsafe { libc::tcgetattr(fd.as_raw_fd(), termios.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: `tcgetattr` filled the structure.
        if unsafe { termios.assume_init() }.c_lflag & libc::ICANON == 0 {
            return None;
        }
        let mut tty = Self {
            fd,
            pending: Vec::new(),
        };
        tty.read_lines().ok()?;
        tty.pending.clear();
        Some(tty)
    }

    /// Reads the input that waits and returns the complete lines.
    fn read_lines(&mut self) -> io::Result<Vec<Vec<u8>>> {
        let mut chunk = [0_u8; 1024];
        loop {
            // SAFETY: `chunk` is valid for its length.
            let count =
                unsafe { libc::read(self.fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
            match usize::try_from(count) {
                // The end-of-file character, or no more input.
                Ok(0) => break,
                Ok(count) => self.pending.extend_from_slice(&chunk[..count]),
                Err(_) => {
                    let error = io::Error::last_os_error();
                    match error.kind() {
                        io::ErrorKind::WouldBlock => break,
                        io::ErrorKind::Interrupted => {}
                        _ => return Err(error),
                    }
                }
            }
        }
        Ok(take_lines(&mut self.pending))
    }
}

/// Opens the terminal of the application, if it is one in line mode.
///
/// # Safety
///
/// `pamh` must be valid.
unsafe fn terminal(pamh: *mut PamHandle) -> Option<Tty> {
    let mut item: *const c_void = std::ptr::null();
    // SAFETY: `pamh` is valid. PAM_TTY is a C string that PAM owns.
    if unsafe { pam_get_item(pamh, PAM_TTY, &raw mut item) } != PAM_SUCCESS || item.is_null() {
        return None;
    }
    // SAFETY: PAM_TTY is a C string.
    let item = unsafe { CStr::from_ptr(item.cast()) }.to_bytes();
    Tty::open(&tty_path(item)?)
}

/// Returns the command that runs the helper.
fn helper_command(program: &str, arguments: &[&OsStr], user: &OsStr, service: &OsStr) -> Command {
    let mut command = Command::new(program);
    command
        .arg("pam-session")
        .args(arguments)
        .env_clear()
        .env("PAM_USER", user)
        .env("PAM_SERVICE", service)
        .env("PAM_TYPE", "auth");
    command
}

/// Returns true if `response` starts a face scan.
fn is_trigger(trigger: Option<&[u8]>, response: &[u8]) -> bool {
    trigger == Some(response)
}

/// The settings of the helper session.
#[derive(Debug)]
struct Greeting {
    prompt: CString,
    reprompt: CString,
    /// `None` if the face factor is disabled.
    trigger: Option<Vec<u8>>,
    /// `finish` prompts once instead of watching the terminal.
    prompt_after: bool,
}

/// A running helper.
#[derive(Debug)]
struct Session {
    child: Child,
    stream: UnixStream,
    buffer: Vec<u8>,
    greeting: Greeting,
    /// `pam_end` runs in a forked process. Leave the helper to the parent.
    abandoned: bool,
}

/// The result of [`Session::open`].
#[derive(Debug)]
enum Opened {
    Session(Box<Session>),
    /// No factor is enabled.
    Off,
}

impl Session {
    /// Runs `command` and reads its settings.
    fn open(mut command: Command) -> Result<Opened, String> {
        let (stream, theirs) = UnixStream::pair().map_err(|error| error.to_string())?;
        let output = theirs.try_clone().map_err(|error| error.to_string())?;
        let child = command
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::from(OwnedFd::from(output)))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("cannot run the helper: {error}"));
        // The command holds the ends of the helper. Close them here, so that
        // the end of the helper gives the end of the stream.
        drop(command);
        let mut session = Self {
            child: child?,
            stream,
            buffer: Vec::new(),
            greeting: Greeting {
                prompt: CString::default(),
                reprompt: CString::default(),
                trigger: None,
                prompt_after: false,
            },
            abandoned: false,
        };
        let deadline = Instant::now() + GREETING_TIMEOUT;
        let (mut prompt, mut reprompt) = (None, None);
        loop {
            let line = match session.read_line(Some(deadline)) {
                Ok(Some(line)) => line,
                Ok(None) => return Err("the helper did not answer in time".to_owned()),
                Err(error) => return Err(format!("the helper ended early: {error}")),
            };
            match Message::parse(&line) {
                Message::Off => {
                    session.stop();
                    return Ok(Opened::Off);
                }
                Message::Prompt(text) => prompt = CString::new(text).ok(),
                Message::Reprompt(text) => reprompt = CString::new(text).ok(),
                Message::Trigger(text) => session.greeting.trigger = Some(text.to_vec()),
                Message::Ready => break,
                Message::AfterPasswordPrompt => session.greeting.prompt_after = true,
                Message::Info(_) | Message::Ask(_) | Message::ScanReply | Message::Unknown => {}
            }
        }
        match (prompt, reprompt) {
            (Some(prompt), Some(reprompt)) => {
                session.greeting.prompt = prompt;
                session.greeting.reprompt = reprompt;
                Ok(Opened::Session(Box::new(session)))
            }
            _ => Err("the helper sent no prompts".to_owned()),
        }
    }

    /// Removes the next complete line from the buffer.
    fn buffered_line(&mut self) -> Option<Vec<u8>> {
        let end = self.buffer.iter().position(|byte| *byte == b'\n')?;
        let mut line: Vec<u8> = self.buffer.drain(..=end).collect();
        line.pop();
        Some(line)
    }

    /// Reads what the helper sent into the buffer. The end of the stream is
    /// an error.
    fn fill(&mut self) -> io::Result<()> {
        if self.buffer.len() > MAX_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        let mut chunk = [0; 4096];
        match (&self.stream).read(&mut chunk) {
            Ok(0) => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => {
                self.buffer.extend_from_slice(&chunk[..count]);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Reads one line. Returns `None` if `deadline` passes first.
    fn read_line(&mut self, deadline: Option<Instant>) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(line) = self.buffered_line() {
                return Ok(Some(line));
            }
            let timeout = match deadline {
                None => -1,
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    c_int::try_from(remaining.as_millis()).unwrap_or(c_int::MAX)
                }
            };
            let mut descriptors = [pollfd(self.stream.as_raw_fd())];
            if poll(&mut descriptors, timeout)? == 0 {
                return Ok(None);
            }
            self.fill()?;
        }
    }

    /// Sends a command. A helper that ended gives an error that the next
    /// read reports as the end of the stream, never SIGPIPE.
    fn send(&self, command: &[u8]) {
        let mut rest = command;
        while !rest.is_empty() {
            // SAFETY: `rest` is valid for its length.
            let sent = unsafe {
                libc::send(
                    self.stream.as_raw_fd(),
                    rest.as_ptr().cast(),
                    rest.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            match usize::try_from(sent) {
                Ok(count) => rest = &rest[count..],
                Err(_) if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    }

    /// Shows the information lines that the helper has sent, without a
    /// wait.
    fn relay(&mut self, conversation: &mut dyn Conversation) {
        while let Ok(Some(line)) = self.read_line(Some(Instant::now())) {
            if let Message::Info(text) = Message::parse(&line) {
                conversation.info(text);
            }
        }
    }

    /// Asks the helper for a face scan and shows its lines until its reply.
    /// The helper shows `Scanning face…` only for a new scan, so a trigger
    /// during a running scan shows nothing new.
    fn request_scan(&mut self, conversation: &mut dyn Conversation) {
        self.send(b"scan\n");
        let deadline = Instant::now() + SCAN_REPLY_TIMEOUT;
        while let Ok(Some(line)) = self.read_line(Some(deadline)) {
            match Message::parse(&line) {
                Message::Info(text) => conversation.info(text),
                Message::ScanReply => return,
                _ => {}
            }
        }
    }

    /// Asks for the password before the password module. Returns
    /// `PAM_IGNORE`, or `PAM_CONV_ERR` if the application gives no
    /// response.
    fn start(&mut self, conversation: &mut dyn Conversation) -> c_int {
        let mut triggers = 0;
        loop {
            self.relay(conversation);
            // The prompts alternate, so that no prompt repeats the one
            // before it.
            let prompt = if triggers % 2 == 1 {
                &self.greeting.reprompt
            } else {
                &self.greeting.prompt
            };
            let Some(response) = conversation.ask(prompt) else {
                return PAM_CONV_ERR;
            };
            if triggers < MAX_TRIGGERS
                && is_trigger(self.greeting.trigger.as_deref(), response.bytes())
            {
                drop(response);
                triggers += 1;
                self.request_scan(conversation);
                continue;
            }
            conversation.set_password(&response);
            return PAM_IGNORE;
        }
    }

    /// Lets the helper wait for a decision after the password module, and
    /// shows its lines meanwhile. Answers an `ask` of the helper with one
    /// prompt. A trigger line on `tty` starts a face scan.
    fn finish(&mut self, conversation: &mut dyn Conversation, mut tty: Option<Tty>) -> Finished {
        self.send(b"finish\n");
        loop {
            while let Some(line) = self.buffered_line() {
                match Message::parse(&line) {
                    Message::Info(text) => conversation.info(text),
                    Message::Ask(text) => {
                        let Some(response) = CString::new(text)
                            .ok()
                            .and_then(|prompt| conversation.ask(&prompt))
                        else {
                            return Finished::ConversationError;
                        };
                        let trigger =
                            is_trigger(self.greeting.trigger.as_deref(), response.bytes());
                        drop(response);
                        // The helper starts the scan and shows its lines.
                        if trigger {
                            self.send(b"answer trigger\n");
                        } else {
                            self.send(b"answer other\n");
                        }
                    }
                    _ => {}
                }
            }
            let mut descriptors = [
                pollfd(self.stream.as_raw_fd()),
                // poll ignores a negative descriptor.
                pollfd(tty.as_ref().map_or(-1, |tty| tty.fd.as_raw_fd())),
            ];
            match poll(&mut descriptors, -1) {
                Ok(_) => {}
                Err(_) => break,
            }
            let [helper, terminal] = descriptors;
            if terminal.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                tty = None;
            } else if terminal.revents & libc::POLLIN != 0
                && let Some(open) = tty.as_mut()
            {
                match open.read_lines() {
                    Ok(lines) => {
                        for line in lines {
                            // The reply comes through the loop. The helper
                            // shows `Scanning face…` for a new scan only.
                            if is_trigger(self.greeting.trigger.as_deref(), &line) {
                                self.send(b"scan\n");
                            }
                        }
                    }
                    Err(_) => tty = None,
                }
            }
            if helper.revents != 0 && self.fill().is_err() {
                break;
            }
        }
        drop(tty);
        Finished::Exited(self.child.wait())
    }

    /// Waits up to `timeout` for the helper to end. Returns true if it
    /// ended. An error means that the application reaped the helper.
    fn wait_for(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return true,
                Ok(None) if Instant::now() >= deadline => return false,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    /// Stops the helper and reaps it: `stop`, then SIGTERM, then SIGKILL.
    fn stop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(None)) {
            return;
        }
        self.send(b"stop\n");
        let _ = self.stream.shutdown(Shutdown::Write);
        if self.wait_for(STOP_GRACE) {
            return;
        }
        if let Ok(pid) = libc::pid_t::try_from(self.child.id()) {
            // SAFETY: The helper is a child that nobody reaped yet, so the
            // PID still belongs to it.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        if self.wait_for(TERM_GRACE) {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.abandoned {
            self.stop();
        }
    }
}

/// Stops the session when PAM drops it.
unsafe extern "C" fn cleanup(_pamh: *mut PamHandle, data: *mut c_void, error_status: c_int) {
    if data.is_null() {
        return;
    }
    // SAFETY: `store` gave PAM this pointer from `Box::into_raw`. PAM calls
    // the cleanup once.
    let mut session = unsafe { Box::from_raw(data.cast::<Session>()) };
    session.abandoned = error_status & PAM_DATA_SILENT != 0;
    let _ = catch_unwind(AssertUnwindSafe(move || drop(session)));
}

/// Returns the stored session.
///
/// # Safety
///
/// `pamh` must be valid. The reference is valid until the next change of
/// the session data.
unsafe fn stored<'a>(pamh: *mut PamHandle) -> Option<&'a mut Session> {
    let mut data: *const c_void = std::ptr::null();
    // SAFETY: `pamh` is valid. The data is a session from `store` or null.
    let found = unsafe { pam_get_data(pamh, DATA_NAME.as_ptr(), &raw mut data) } == PAM_SUCCESS;
    // SAFETY: `store` set the data to a boxed session. Only this module
    // uses the name.
    (found && !data.is_null()).then(|| unsafe { &mut *data.cast::<Session>().cast_mut() })
}

/// Hands `session` to PAM. Returns a reference that is valid until the
/// next change of the session data.
///
/// # Safety
///
/// `pamh` must be valid.
unsafe fn store<'a>(pamh: *mut PamHandle, session: Box<Session>) -> Option<&'a mut Session> {
    let raw = Box::into_raw(session);
    // SAFETY: `pamh` is valid. PAM calls `cleanup` with `raw` once.
    if unsafe { pam_set_data(pamh, DATA_NAME.as_ptr(), raw.cast(), Some(cleanup)) } != PAM_SUCCESS {
        // SAFETY: PAM did not take the pointer.
        drop(unsafe { Box::from_raw(raw) });
        return None;
    }
    // SAFETY: PAM holds the box until the next change of the data.
    Some(unsafe { &mut *raw })
}

/// Stops and removes the stored session.
///
/// # Safety
///
/// `pamh` must be valid. No reference from [`stored`] or [`store`] may
/// remain in use.
unsafe fn remove(pamh: *mut PamHandle) {
    // SAFETY: `pamh` is valid. PAM calls the cleanup of the old data.
    unsafe { pam_set_data(pamh, DATA_NAME.as_ptr(), std::ptr::null_mut(), None) };
}

/// Starts a helper session and stores it.
///
/// # Safety
///
/// `pamh` must be valid.
unsafe fn open<'a>(pamh: *mut PamHandle, arguments: &[&OsStr]) -> Option<&'a mut Session> {
    let mut user: *const c_char = std::ptr::null();
    // SAFETY: `pamh` is valid. `user` receives a string that PAM owns.
    if unsafe { pam_get_user(pamh, &raw mut user, std::ptr::null()) } != PAM_SUCCESS
        || user.is_null()
    {
        return None;
    }
    // SAFETY: PAM returned a valid C string.
    let user = OsStr::from_bytes(unsafe { CStr::from_ptr(user) }.to_bytes());

    let mut service: *const c_void = std::ptr::null();
    // SAFETY: `pamh` is valid. PAM_SERVICE is a C string that PAM owns.
    let service = if unsafe { pam_get_item(pamh, PAM_SERVICE, &raw mut service) } == PAM_SUCCESS
        && !service.is_null()
    {
        // SAFETY: PAM_SERVICE is a C string.
        OsStr::from_bytes(unsafe { CStr::from_ptr(service.cast()) }.to_bytes())
    } else {
        OsStr::new("")
    };

    match Session::open(helper_command(HELPER, arguments, user, service)) {
        // SAFETY: `pamh` is valid.
        Ok(Opened::Session(session)) => unsafe { store(pamh, session) },
        Ok(Opened::Off) => None,
        Err(error) => {
            log(pamh, LOG_ERR, &format!("{HELPER}: {error}"));
            None
        }
    }
}

/// # Safety
///
/// `pamh` must be a valid PAM handle. `argv` must hold `argc` C strings.
unsafe fn authenticate(pamh: *mut PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: The caller guarantees `argc` and `argv`.
    let arguments = unsafe { arguments(argc, argv) };
    let (mode, arguments) = mode(&arguments);
    let mut conversation = Pam(pamh);
    match mode {
        Mode::Start => {
            // A new attempt with the same handle replaces the old session.
            // SAFETY: `pamh` is valid. No session reference exists.
            unsafe { remove(pamh) };
            // SAFETY: `pamh` is valid.
            let Some(session) = (unsafe { open(pamh, arguments) }) else {
                return PAM_IGNORE;
            };
            let result = session.start(&mut conversation);
            if result != PAM_IGNORE {
                // The application aborted. `finish` does not run.
                // SAFETY: `pamh` is valid. `session` is no longer used.
                unsafe { remove(pamh) };
            }
            result
        }
        Mode::Finish => {
            // SAFETY: `pamh` is valid.
            let session = unsafe { stored(pamh) }.or_else(|| unsafe { open(pamh, arguments) });
            let Some(session) = session else {
                return PAM_IGNORE;
            };
            // Only a face trigger can come from the terminal, and only
            // `after_password: wait` watches it.
            let tty = (session.greeting.trigger.is_some() && !session.greeting.prompt_after)
                // SAFETY: `pamh` is valid.
                .then(|| unsafe { terminal(pamh) })
                .flatten();
            let result = match session.finish(&mut conversation, tty) {
                Finished::Exited(Ok(status)) => {
                    let result = pam_result(status.code());
                    if result == PAM_IGNORE {
                        log(
                            pamh,
                            LOG_WARNING,
                            &format!("helper gave no decision ({status})"),
                        );
                    }
                    result
                }
                Finished::Exited(Err(error)) => {
                    log(pamh, LOG_ERR, &format!("waitpid: {error}"));
                    PAM_IGNORE
                }
                Finished::ConversationError => PAM_CONV_ERR,
            };
            // SAFETY: `pamh` is valid. `session` is no longer used.
            unsafe { remove(pamh) };
            result
        }
    }
}

/// The auth entry point.
///
/// # Safety
///
/// PAM calls this function with a valid handle and arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: PAM passes a valid handle and arguments.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        authenticate(pamh, argc, argv)
    }))
    .unwrap_or(PAM_IGNORE)
}

/// The credential entry point. This module sets no credentials.
///
/// # Safety
///
/// PAM calls this function with a valid handle and arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// A scripted conversation.
    #[derive(Default)]
    struct Script {
        responses: VecDeque<&'static str>,
        prompts: Vec<String>,
        infos: Vec<String>,
        password: Option<String>,
    }

    impl Script {
        fn new(responses: &[&'static str]) -> Self {
            Self {
                responses: responses.iter().copied().collect(),
                ..Self::default()
            }
        }
    }

    impl Conversation for Script {
        fn info(&mut self, text: &[u8]) {
            self.infos.push(String::from_utf8(text.to_vec()).unwrap());
        }

        fn ask(&mut self, prompt: &CStr) -> Option<Secret> {
            self.prompts.push(prompt.to_str().unwrap().to_owned());
            let response = CString::new(self.responses.pop_front()?).unwrap();
            // SAFETY: strdup copies a valid C string with malloc.
            Some(Secret(unsafe { libc::strdup(response.as_ptr()) }))
        }

        fn set_password(&mut self, password: &Secret) {
            self.password = Some(String::from_utf8(password.bytes().to_vec()).unwrap());
        }
    }

    /// Runs a shell script as the helper.
    fn helper(script: &str) -> Result<Opened, String> {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        Session::open(command)
    }

    fn start_helper(script: &str) -> Session {
        match helper(script) {
            Ok(Opened::Session(session)) => *session,
            Ok(Opened::Off) => panic!("the helper is off"),
            Err(error) => panic!("{error}"),
        }
    }

    const GREETING: &str =
        r"printf 'prompt Password (Enter to scan face): \nreprompt Password: \ntrigger \nready\n'";

    /// Echoes each command as an information line, and answers `scan` like
    /// the helper with a new scan.
    const ECHO: &str = r#"while read -r command; do echo "info got $command"; if [ "$command" = scan ]; then echo 'info Scanning face…'; echo 'scan started'; fi; done"#;

    /// Like [`ECHO`], with a scan that runs already.
    const ECHO_RUNNING: &str = r#"while read -r command; do echo "info got $command"; if [ "$command" = scan ]; then echo 'scan running'; fi; done"#;

    fn gone(pid: u32) -> bool {
        // SAFETY: Signal 0 only checks the PID. A zombie still has its PID.
        let result = unsafe { libc::kill(libc::pid_t::try_from(pid).unwrap(), 0) };
        result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    fn next_line(session: &mut Session) -> String {
        let line = session
            .read_line(Some(Instant::now() + Duration::from_secs(5)))
            .unwrap()
            .unwrap();
        String::from_utf8(line).unwrap()
    }

    #[test]
    fn exit_codes_map_to_pam_results() {
        assert_eq!(pam_result(Some(0)), PAM_SUCCESS);
        assert_eq!(pam_result(Some(10)), PAM_AUTH_ERR);
        assert_eq!(pam_result(Some(20)), PAM_IGNORE);
        assert_eq!(pam_result(Some(1)), PAM_IGNORE);
        assert_eq!(pam_result(Some(127)), PAM_IGNORE);
        assert_eq!(pam_result(None), PAM_IGNORE);
    }

    #[test]
    fn module_arguments() {
        let first = c"start";
        let second = c"--policy=/etc/other.json";
        let argv = [first.as_ptr(), second.as_ptr()];
        // SAFETY: `argv` holds two valid C strings.
        let converted = unsafe { arguments(2, argv.as_ptr()) };
        assert_eq!(
            converted,
            [OsStr::new("start"), OsStr::new("--policy=/etc/other.json")]
        );
        assert_eq!(
            mode(&converted),
            (Mode::Start, &[OsStr::new("--policy=/etc/other.json")][..])
        );
        // SAFETY: A count of 0 does not read `argv`.
        assert!(unsafe { arguments(0, std::ptr::null()) }.is_empty());
    }

    #[test]
    fn modes() {
        let finish = [OsStr::new("finish")];
        assert_eq!(mode(&finish), (Mode::Finish, &[][..]));
        // Without a mode, the module runs finish with all arguments.
        assert_eq!(mode(&[]), (Mode::Finish, &[][..]));
        let other = [OsStr::new("--socket=/tmp/socket")];
        assert_eq!(mode(&other), (Mode::Finish, &other[..]));
        let later = [OsStr::new("--socket=/tmp/socket"), OsStr::new("start")];
        assert_eq!(mode(&later), (Mode::Finish, &later[..]));
    }

    #[test]
    fn helper_environment() {
        let command = helper_command(
            "/run/pam-biometrics",
            &[OsStr::new("--policy=/etc/other.json")],
            OsStr::new("alice"),
            OsStr::new("sudo"),
        );
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["pam-session", "--policy=/etc/other.json"]
        );
        let mut variables: Vec<_> = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(OsStr::to_owned)))
            .collect();
        variables.sort();
        assert_eq!(
            variables,
            [
                ("PAM_SERVICE".into(), Some("sudo".into())),
                ("PAM_TYPE".into(), Some("auth".into())),
                ("PAM_USER".into(), Some("alice".into())),
            ]
        );
    }

    #[test]
    fn messages_parse() {
        assert_eq!(Message::parse(b"off"), Message::Off);
        assert_eq!(Message::parse(b"ready"), Message::Ready);
        assert_eq!(
            Message::parse(b"prompt Password: "),
            Message::Prompt(b"Password: ")
        );
        assert_eq!(Message::parse(b"reprompt P"), Message::Reprompt(b"P"));
        // An empty trigger stands for Enter alone.
        assert_eq!(Message::parse(b"trigger "), Message::Trigger(b""));
        assert_eq!(Message::parse(b"trigger"), Message::Trigger(b""));
        assert_eq!(Message::parse(b"trigger f"), Message::Trigger(b"f"));
        assert_eq!(
            Message::parse(b"info Face recognized."),
            Message::Info(b"Face recognized.")
        );
        assert_eq!(Message::parse(b"ask Touch: "), Message::Ask(b"Touch: "));
        assert_eq!(
            Message::parse(b"after-password prompt"),
            Message::AfterPasswordPrompt
        );
        assert_eq!(Message::parse(b"after-password wait"), Message::Unknown);
        assert_eq!(Message::parse(b"state pending idle"), Message::Unknown);
        assert_eq!(Message::parse(b""), Message::Unknown);
    }

    #[test]
    fn triggers() {
        assert!(is_trigger(Some(b""), b""));
        assert!(!is_trigger(Some(b""), b"secret"));
        assert!(is_trigger(Some(b"f"), b"f"));
        assert!(!is_trigger(Some(b"f"), b""));
        assert!(!is_trigger(Some(b"f"), b"ff"));
        // Without the face factor, nothing is a trigger.
        assert!(!is_trigger(None, b""));
    }

    #[test]
    fn greeting_and_commands() {
        let mut session = start_helper(&format!("{GREETING}; {ECHO}"));
        assert_eq!(
            session.greeting.prompt.as_c_str(),
            c"Password (Enter to scan face): "
        );
        assert_eq!(session.greeting.reprompt.as_c_str(), c"Password: ");
        assert_eq!(session.greeting.trigger.as_deref(), Some(&b""[..]));
        session.send(b"state\n");
        assert_eq!(next_line(&mut session), "info got state");
        // Nothing waits: the read returns at the deadline.
        assert_eq!(session.read_line(Some(Instant::now())).unwrap(), None);
    }

    #[test]
    fn off_and_failures() {
        assert!(matches!(helper("echo off"), Ok(Opened::Off)));
        assert!(helper("exit 0").is_err());
        assert!(helper("printf 'prompt P: \\nready\\n'").is_err());
        let error = Session::open(Command::new("/nonexistent/pam-biometrics")).unwrap_err();
        assert!(error.starts_with("cannot run the helper"), "{error}");
    }

    #[test]
    fn password_only() {
        let mut session = start_helper(&format!("{GREETING}; {ECHO}"));
        let mut script = Script::new(&["secret"]);
        assert_eq!(session.start(&mut script), PAM_IGNORE);
        assert_eq!(script.prompts, ["Password (Enter to scan face): "]);
        assert_eq!(script.password.as_deref(), Some("secret"));
        assert!(script.infos.is_empty());
    }

    #[test]
    fn trigger_then_password() {
        let mut session = start_helper(&format!("{GREETING}; {ECHO}"));
        let mut script = Script::new(&["", "", "secret"]);
        assert_eq!(session.start(&mut script), PAM_IGNORE);
        assert_eq!(
            script.prompts,
            [
                "Password (Enter to scan face): ",
                "Password: ",
                "Password (Enter to scan face): "
            ]
        );
        assert_eq!(script.password.as_deref(), Some("secret"));
        // `start` waits for each reply, so the lines of the helper come in
        // order and before the next prompt.
        assert_eq!(
            script.infos,
            ["got scan", "Scanning face…", "got scan", "Scanning face…"]
        );
    }

    #[test]
    fn trigger_during_a_running_scan_shows_nothing_new() {
        let mut session = start_helper(&format!("{GREETING}; {ECHO_RUNNING}"));
        let mut script = Script::new(&["", "secret"]);
        assert_eq!(session.start(&mut script), PAM_IGNORE);
        assert_eq!(script.prompts.len(), 2);
        assert_eq!(script.infos, ["got scan"]);
        assert_eq!(script.password.as_deref(), Some("secret"));
    }

    #[test]
    fn custom_trigger() {
        let mut session = start_helper(&format!(
            "printf 'prompt Password (type f to scan face): \\nreprompt Password: \\ntrigger f\\nready\\n'; {ECHO}"
        ));
        let mut script = Script::new(&["f", ""]);
        assert_eq!(session.start(&mut script), PAM_IGNORE);
        assert_eq!(script.prompts.len(), 2);
        // An empty response is the password here.
        assert_eq!(script.password.as_deref(), Some(""));
    }

    #[test]
    fn triggers_are_limited() {
        let mut session = start_helper(&format!("{GREETING}; {ECHO}"));
        let mut script = Script::new(&["", "", "", "", "", ""]);
        assert_eq!(session.start(&mut script), PAM_IGNORE);
        assert_eq!(script.prompts.len(), 6);
        for pair in script.prompts.windows(2) {
            assert_ne!(pair[0], pair[1]);
        }
        assert_eq!(script.password.as_deref(), Some(""));
    }

    #[test]
    fn without_face_the_trigger_is_a_password() {
        let mut session = start_helper(&format!(
            "printf 'prompt Password: \\nreprompt Password (face scan started): \\nready\\n'; {ECHO}"
        ));
        let mut script = Script::new(&[""]);
        assert_eq!(session.start(&mut script), PAM_IGNORE);
        assert_eq!(script.password.as_deref(), Some(""));
        assert!(script.infos.is_empty());
    }

    #[test]
    fn aborted_conversation() {
        let mut session = start_helper(&format!("{GREETING}; {ECHO}"));
        let mut script = Script::new(&[]);
        assert_eq!(session.start(&mut script), PAM_CONV_ERR);
        assert_eq!(script.password, None);
    }

    /// A pseudo terminal. The test types on the master end.
    struct Pty {
        master: OwnedFd,
        slave: OwnedFd,
        path: PathBuf,
    }

    impl Pty {
        fn new() -> Self {
            let (mut master, mut slave) = (0, 0);
            // SAFETY: openpty writes two descriptors. Null pointers leave
            // the name, the settings, and the size alone.
            let result = unsafe {
                libc::openpty(
                    &raw mut master,
                    &raw mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            assert_eq!(result, 0, "{}", io::Error::last_os_error());
            // SAFETY: openpty returned two new descriptors.
            let (master, slave) =
                unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
            let path = std::fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
            Self {
                master,
                slave,
                path,
            }
        }

        fn type_text(&self, text: &[u8]) {
            // SAFETY: `text` is valid for its length.
            let written =
                unsafe { libc::write(self.master.as_raw_fd(), text.as_ptr().cast(), text.len()) };
            assert_eq!(usize::try_from(written).unwrap(), text.len());
        }

        fn set_line_mode(&self, on: bool) {
            let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
            // SAFETY: tcgetattr fills the structure, tcsetattr reads it.
            unsafe {
                assert_eq!(
                    libc::tcgetattr(self.slave.as_raw_fd(), termios.as_mut_ptr()),
                    0
                );
                let mut termios = termios.assume_init();
                if on {
                    termios.c_lflag |= libc::ICANON;
                } else {
                    termios.c_lflag &= !libc::ICANON;
                }
                assert_eq!(
                    libc::tcsetattr(self.slave.as_raw_fd(), libc::TCSANOW, &raw const termios),
                    0
                );
            }
        }
    }

    /// Reads lines from `tty` until `count` lines or 5 s.
    fn tty_lines(tty: &mut Tty, count: usize) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut lines = Vec::new();
        while lines.len() < count && Instant::now() < deadline {
            let mut descriptors = [pollfd(tty.fd.as_raw_fd())];
            poll(&mut descriptors, 100).unwrap();
            lines.extend(tty.read_lines().unwrap());
        }
        lines
    }

    #[test]
    fn tty_paths() {
        assert_eq!(tty_path(b"tty1"), Some(PathBuf::from("/dev/tty1")));
        assert_eq!(tty_path(b"pts/3"), Some(PathBuf::from("/dev/pts/3")));
        assert_eq!(tty_path(b"/dev/pts/3"), Some(PathBuf::from("/dev/pts/3")));
        for item in [
            &b""[..],
            b":0",
            b"/etc/passwd",
            b"/dev/../etc/passwd",
            b"../etc/passwd",
            b"pts/../../etc/passwd",
        ] {
            assert_eq!(tty_path(item), None, "{}", String::from_utf8_lossy(item));
        }
    }

    #[test]
    fn lines_split() {
        let mut pending = b"x\n\r\n\nab".to_vec();
        assert_eq!(take_lines(&mut pending), [&b"x"[..], b"", b""]);
        assert_eq!(pending, b"ab");
        pending.extend_from_slice(b"c\n");
        assert_eq!(take_lines(&mut pending), [&b"abc"[..]]);
        // A partial line beyond the limit is dropped.
        let mut long = vec![b'a'; MAX_TTY_LINE + 1];
        assert!(take_lines(&mut long).is_empty());
        assert!(long.is_empty());
    }

    #[test]
    fn tty_reads_lines_in_line_mode() {
        let pty = Pty::new();
        // Input from before the wait does not count.
        pty.type_text(b"stale\n");
        std::thread::sleep(Duration::from_millis(200));
        let mut tty = Tty::open(&pty.path).expect("a terminal in line mode");
        assert!(tty.read_lines().unwrap().is_empty());
        pty.type_text(b"x\n\n");
        assert_eq!(tty_lines(&mut tty, 2), [&b"x"[..], b""]);
    }

    #[test]
    fn tty_without_line_mode_or_a_terminal_is_not_read() {
        let pty = Pty::new();
        pty.set_line_mode(false);
        assert!(Tty::open(&pty.path).is_none());
        pty.set_line_mode(true);
        assert!(Tty::open(&pty.path).is_some());
        // A character device that is not a terminal.
        assert!(Tty::open(Path::new("/dev/null")).is_none());
        // A regular file, and a missing file.
        assert!(Tty::open(Path::new("/proc/self/status")).is_none());
        assert!(Tty::open(Path::new("/dev/pam-biometrics-missing")).is_none());
    }

    #[test]
    fn tty_trigger_during_the_wait_starts_a_scan() {
        let script = format!(
            r#"{GREETING}
read -r command; echo "info got $command"; echo 'info Wait.'
read -r command; echo "info got $command"
exit 0"#
        );
        let mut session = start_helper(&script);
        let pty = Pty::new();
        let tty = Tty::open(&pty.path).expect("a terminal in line mode");
        let typist = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            // Lines other than the trigger do nothing.
            pty.type_text(b"hello\n");
            std::thread::sleep(Duration::from_millis(100));
            pty.type_text(b"\n");
            // Keep the terminal open until the helper ends.
            std::thread::sleep(Duration::from_secs(2));
        });
        let mut conversation = Script::new(&[]);
        let status = exited(session.finish(&mut conversation, Some(tty)));
        assert_eq!(pam_result(status.code()), PAM_SUCCESS);
        assert_eq!(conversation.infos, ["got finish", "Wait.", "got scan"]);
        assert!(conversation.prompts.is_empty());
        drop(typist);
    }

    #[test]
    fn finish_relays_and_maps_the_exit_code() {
        let script = format!(
            r"{GREETING}; read -r command; echo 'info Wait.'; sleep 0.2
echo 'info Face not recognized.'; echo 'info Not recognized.'; exit 10"
        );
        let mut session = start_helper(&script);
        let mut conversation = Script::new(&[]);
        let status = exited(session.finish(&mut conversation, None));
        assert_eq!(pam_result(status.code()), PAM_AUTH_ERR);
        assert_eq!(
            conversation.infos,
            ["Wait.", "Face not recognized.", "Not recognized."]
        );
        assert!(conversation.prompts.is_empty());

        let mut session = start_helper(&format!("{GREETING}; read -r command; exit 20"));
        let status = exited(session.finish(&mut Script::new(&[]), None));
        assert_eq!(pam_result(status.code()), PAM_IGNORE);
    }

    #[test]
    fn finish_after_a_crash_gives_no_decision() {
        let mut session = start_helper(&format!("{GREETING}; read -r command; kill -9 $$"));
        let status = exited(session.finish(&mut Script::new(&[]), None));
        assert_eq!(pam_result(status.code()), PAM_IGNORE);
    }

    fn exited(finished: Finished) -> ExitStatus {
        match finished {
            Finished::Exited(status) => status.unwrap(),
            Finished::ConversationError => panic!("conversation error"),
        }
    }

    /// A helper with `after_password: prompt` that asks once, echoes the
    /// answer, and exits with `code`.
    fn asking_helper(code: u8) -> Session {
        let session = start_helper(&format!(
            r#"printf 'prompt Password (Enter to scan face): \nreprompt Password: \ntrigger \nafter-password prompt\nready\n'
read -r command; echo 'info Fingerprint not recognized. Try again.'
echo 'ask Touch the fingerprint reader or press Enter to scan your face (other text skips): '
read -r answer; echo "info got $answer"; exit {code}"#
        ));
        assert!(session.greeting.prompt_after);
        session
    }

    #[test]
    fn finish_answers_the_prompt_with_the_trigger() {
        let mut session = asking_helper(0);
        let mut conversation = Script::new(&[""]);
        let status = exited(session.finish(&mut conversation, None));
        assert_eq!(pam_result(status.code()), PAM_SUCCESS);
        assert_eq!(
            conversation.prompts,
            ["Touch the fingerprint reader or press Enter to scan your face (other text skips): "]
        );
        // The helper shows `Scanning face…` for a new scan.
        assert_eq!(
            conversation.infos,
            [
                "Fingerprint not recognized. Try again.",
                "got answer trigger"
            ]
        );
    }

    #[test]
    fn finish_answers_the_prompt_with_other_text() {
        let mut session = asking_helper(20);
        let mut conversation = Script::new(&["skip"]);
        let status = exited(session.finish(&mut conversation, None));
        assert_eq!(pam_result(status.code()), PAM_IGNORE);
        assert_eq!(
            conversation.infos,
            ["Fingerprint not recognized. Try again.", "got answer other"]
        );
    }

    #[test]
    fn finish_prompt_conversation_error() {
        let mut session = asking_helper(0);
        assert!(matches!(
            session.finish(&mut Script::new(&[]), None),
            Finished::ConversationError
        ));
        // Dropping the session stops the helper.
        let pid = session.child.id();
        drop(session);
        assert!(gone(pid));
    }

    #[test]
    fn greeting_without_the_prompt_mode() {
        let session = start_helper(&format!("{GREETING}; {ECHO}"));
        assert!(!session.greeting.prompt_after);
    }

    #[test]
    fn stop_ends_a_helper_that_reads_commands() {
        let session = start_helper(&format!("{GREETING}; {ECHO}"));
        let pid = session.child.id();
        let start = Instant::now();
        drop(session);
        assert!(start.elapsed() < STOP_GRACE, "{:?}", start.elapsed());
        assert!(gone(pid));
    }

    #[test]
    fn stop_kills_a_stuck_helper() {
        let mut session = start_helper(&format!("trap '' TERM; {GREETING}; exec sleep 30"));
        let pid = session.child.id();
        let start = Instant::now();
        session.stop();
        assert!(start.elapsed() >= STOP_GRACE);
        assert!(start.elapsed() < STOP_GRACE + TERM_GRACE + Duration::from_secs(1));
        assert!(gone(pid));
        // A second stop does nothing.
        session.stop();
    }

    #[test]
    fn abandoned_sessions_leave_the_helper() {
        let mut session = start_helper(&format!("{GREETING}; exec sleep 30"));
        let pid = session.child.id();
        session.abandoned = true;
        drop(session);
        assert!(!gone(pid));
        let pid = libc::pid_t::try_from(pid).unwrap();
        // SAFETY: The helper is a child of this process that nobody reaped.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }
}
