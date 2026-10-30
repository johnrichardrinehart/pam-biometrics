//! A client of fprintd on the system D-Bus.
//!
//! The [`Fprintd`] and [`Device`] traits cover the calls that the finger
//! commands use, so that tests can replace fprintd with a mock.

use zbus::blocking::proxy::SignalIterator;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

/// The bus name of fprintd.
pub const SERVICE: &str = "net.reactivated.Fprint";
/// The object path of the fprintd manager.
pub const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
/// The interface of the fprintd manager.
pub const MANAGER_INTERFACE: &str = "net.reactivated.Fprint.Manager";
/// The interface of an fprintd device.
pub const DEVICE_INTERFACE: &str = "net.reactivated.Fprint.Device";

/// The D-Bus error for a user without enrolled fingers.
pub const NO_ENROLLED_PRINTS: &str = "net.reactivated.Fprint.Error.NoEnrolledPrints";

/// The finger names that fprintd accepts, in the order of fprintd.
pub const FINGER_NAMES: [&str; 10] = [
    "left-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "right-thumb",
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
];

/// The finger name that matches every enrolled finger in a verification.
pub const ANY_FINGER: &str = "any";

/// An error from fprintd or from the bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The D-Bus error name, if the error is a D-Bus error reply.
    pub name: Option<String>,
    /// The error text.
    pub message: String,
}

impl Error {
    /// Returns true if the D-Bus error name is `name`.
    #[must_use]
    pub fn is(&self, name: &str) -> bool {
        self.name.as_deref() == Some(name)
    }
}

impl From<zbus::Error> for Error {
    fn from(error: zbus::Error) -> Self {
        match error {
            zbus::Error::MethodError(name, description, _) => Self {
                message: description.unwrap_or_else(|| name.to_string()),
                name: Some(name.to_string()),
            },
            other => Self {
                name: None,
                message: other.to_string(),
            },
        }
    }
}

/// A signal of an fprintd device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// `VerifyStatus(result, done)`.
    VerifyStatus {
        /// The result name, for example `verify-match`.
        result: String,
        /// True if the verification ended.
        done: bool,
    },
    /// `VerifyFingerSelected(finger)`.
    VerifyFingerSelected(String),
    /// `EnrollStatus(result, done)`.
    EnrollStatus {
        /// The result name, for example `enroll-stage-passed`.
        result: String,
        /// True if the enrollment ended.
        done: bool,
    },
}

/// The fprintd manager.
pub trait Fprintd {
    /// The device type.
    type Device: Device;

    /// `GetDevices`: the object paths of all devices.
    fn devices(&self) -> Result<Vec<String>, Error>;

    /// `GetDefaultDevice`: the object path of the default device.
    fn default_device(&self) -> Result<String, Error>;

    /// Connects to the device at `path`.
    fn device(&self, path: &str) -> Result<Self::Device, Error>;
}

/// An fprintd device.
pub trait Device {
    /// The `name` property.
    fn name(&self) -> Result<String, Error>;
    /// The `scan-type` property.
    fn scan_type(&self) -> Result<String, Error>;
    /// `Claim(user)`.
    fn claim(&self, user: &str) -> Result<(), Error>;
    /// `Release()`.
    fn release(&self) -> Result<(), Error>;
    /// `ListEnrolledFingers(user)`.
    fn list_enrolled_fingers(&self, user: &str) -> Result<Vec<String>, Error>;
    /// `DeleteEnrolledFingers2()`: deletes all fingers of the claimed user.
    fn delete_enrolled_fingers(&self) -> Result<(), Error>;
    /// `DeleteEnrolledFinger(finger)`.
    fn delete_enrolled_finger(&self, finger: &str) -> Result<(), Error>;
    /// Subscribes to the device signals, then calls `VerifyStart(finger)`.
    fn verify_start(&mut self, finger: &str) -> Result<(), Error>;
    /// `VerifyStop()`.
    fn verify_stop(&self) -> Result<(), Error>;
    /// Subscribes to the device signals, then calls `EnrollStart(finger)`.
    fn enroll_start(&mut self, finger: &str) -> Result<(), Error>;
    /// `EnrollStop()`.
    fn enroll_stop(&self) -> Result<(), Error>;
    /// Waits for the next device signal. Returns `None` if the bus
    /// connection ends.
    fn next_signal(&mut self) -> Option<Signal>;
}

/// fprintd on the system bus.
#[derive(Debug)]
pub struct SystemFprintd {
    connection: Connection,
    manager: Proxy<'static>,
}

impl SystemFprintd {
    /// Connects to the system bus.
    pub fn connect() -> Result<Self, Error> {
        let connection = Connection::system()?;
        let manager = Proxy::new(&connection, SERVICE, MANAGER_PATH, MANAGER_INTERFACE)?;
        Ok(Self {
            connection,
            manager,
        })
    }
}

impl Fprintd for SystemFprintd {
    type Device = SystemDevice;

    fn devices(&self) -> Result<Vec<String>, Error> {
        let paths: Vec<OwnedObjectPath> = self.manager.call("GetDevices", &())?;
        Ok(paths.iter().map(ToString::to_string).collect())
    }

    fn default_device(&self) -> Result<String, Error> {
        let path: OwnedObjectPath = self.manager.call("GetDefaultDevice", &())?;
        Ok(path.to_string())
    }

    fn device(&self, path: &str) -> Result<SystemDevice, Error> {
        let path =
            zbus::zvariant::ObjectPath::try_from(path.to_owned()).map_err(zbus::Error::from)?;
        let proxy = Proxy::new(&self.connection, SERVICE, path, DEVICE_INTERFACE)?;
        Ok(SystemDevice {
            proxy,
            signals: None,
        })
    }
}

/// A device of [`SystemFprintd`].
pub struct SystemDevice {
    proxy: Proxy<'static>,
    signals: Option<SignalIterator<'static>>,
}

impl std::fmt::Debug for SystemDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemDevice")
            .field("path", &self.proxy.path())
            .finish_non_exhaustive()
    }
}

impl SystemDevice {
    fn subscribe(&mut self) -> Result<(), Error> {
        if self.signals.is_none() {
            self.signals = Some(self.proxy.receive_all_signals()?);
        }
        Ok(())
    }
}

impl Device for SystemDevice {
    fn name(&self) -> Result<String, Error> {
        Ok(self.proxy.get_property("name")?)
    }

    fn scan_type(&self) -> Result<String, Error> {
        Ok(self.proxy.get_property("scan-type")?)
    }

    fn claim(&self, user: &str) -> Result<(), Error> {
        Ok(self.proxy.call("Claim", &(user,))?)
    }

    fn release(&self) -> Result<(), Error> {
        Ok(self.proxy.call("Release", &())?)
    }

    fn list_enrolled_fingers(&self, user: &str) -> Result<Vec<String>, Error> {
        Ok(self.proxy.call("ListEnrolledFingers", &(user,))?)
    }

    fn delete_enrolled_fingers(&self) -> Result<(), Error> {
        Ok(self.proxy.call("DeleteEnrolledFingers2", &())?)
    }

    fn delete_enrolled_finger(&self, finger: &str) -> Result<(), Error> {
        Ok(self.proxy.call("DeleteEnrolledFinger", &(finger,))?)
    }

    fn verify_start(&mut self, finger: &str) -> Result<(), Error> {
        self.subscribe()?;
        Ok(self.proxy.call("VerifyStart", &(finger,))?)
    }

    fn verify_stop(&self) -> Result<(), Error> {
        Ok(self.proxy.call("VerifyStop", &())?)
    }

    fn enroll_start(&mut self, finger: &str) -> Result<(), Error> {
        self.subscribe()?;
        Ok(self.proxy.call("EnrollStart", &(finger,))?)
    }

    fn enroll_stop(&self) -> Result<(), Error> {
        Ok(self.proxy.call("EnrollStop", &())?)
    }

    fn next_signal(&mut self) -> Option<Signal> {
        let signals = self.signals.as_mut()?;
        for message in signals.by_ref() {
            let header = message.header();
            let Some(member) = header.member() else {
                continue;
            };
            let body = message.body();
            let signal = match member.as_str() {
                "VerifyStatus" => body
                    .deserialize::<(String, bool)>()
                    .ok()
                    .map(|(result, done)| Signal::VerifyStatus { result, done }),
                "VerifyFingerSelected" => body
                    .deserialize::<(String,)>()
                    .ok()
                    .map(|(finger,)| Signal::VerifyFingerSelected(finger)),
                "EnrollStatus" => body
                    .deserialize::<(String, bool)>()
                    .ok()
                    .map(|(result, done)| Signal::EnrollStatus { result, done }),
                _ => None,
            };
            if signal.is_some() {
                return signal;
            }
        }
        None
    }
}
