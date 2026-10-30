//! Request handling, authorization, and the stored scan results.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use pam_biometrics_policy::Policy;
use pam_biometrics_protocol::{Op, Reply, Request, ScanResult};

use crate::model;
use crate::scanner::{Scan, Scanner};

/// Looks up users in the system user database.
pub trait UserDb: Send + Sync + 'static {
    /// Returns the canonical name and the UID of `name`.
    fn lookup(&self, name: &str) -> Option<(String, u32)>;
}

/// The [`UserDb`] of the system, through NSS.
#[derive(Debug)]
pub struct SystemUsers;

impl UserDb for SystemUsers {
    fn lookup(&self, name: &str) -> Option<(String, u32)> {
        let user = nix::unistd::User::from_name(name).ok()??;
        Some((user.name, user.uid.as_raw()))
    }
}

/// Daemon settings that the handlers use.
#[derive(Clone, Debug)]
pub struct Config {
    /// The directory of the model files.
    pub state_dir: PathBuf,
    /// The camera device. Every reply includes it.
    pub device: String,
    /// The policy file. Scans stop early at its strictest match distance.
    pub policy: PathBuf,
    /// A finished result expires after this time.
    pub result_ttl: Duration,
    /// `wait` and `take` wait at most this long for a running scan.
    pub settle_limit: Duration,
    /// This UID can start scans for any user.
    pub greeter_uid: Option<u32>,
}

struct Stored {
    result: ScanResult,
    /// `None` while the scan runs.
    finished: Option<Instant>,
}

/// The daemon state that the connection threads share.
pub struct Service<S> {
    config: Config,
    users: Box<dyn UserDb>,
    scanner: Mutex<S>,
    results: Mutex<HashMap<String, Stored>>,
    changed: Condvar,
}

impl<S> std::fmt::Debug for Service<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn describe(result: &ScanResult) -> String {
    match result {
        ScanResult::Scanning => "scanning".to_owned(),
        ScanResult::NoModel => "no-model".to_owned(),
        ScanResult::Finished { best, faces } => {
            let best = best.map_or_else(|| "none".to_owned(), |best| format!("{best:.4}"));
            format!("finished best={best} faces={faces}")
        }
    }
}

impl<S: Scanner> Service<S> {
    /// Creates the shared state.
    pub fn new(config: Config, users: Box<dyn UserDb>, scanner: S) -> Arc<Self> {
        Arc::new(Self {
            config,
            users,
            scanner: Mutex::new(scanner),
            results: Mutex::new(HashMap::new()),
            changed: Condvar::new(),
        })
    }

    /// Handles one request from a client with `uid`.
    pub fn handle(self: &Arc<Self>, uid: u32, request: &Request) -> Reply {
        let Some((user, user_uid)) = self.users.lookup(&request.user) else {
            return Reply::error("unknown user");
        };
        let greeter = request.op == Op::Scan && self.config.greeter_uid == Some(uid);
        if !(uid == 0 || uid == user_uid || greeter) {
            return Reply::error("permission denied");
        }
        let reply = match request.op {
            Op::Scan => self.start_scan(&user),
            Op::Status => Ok(self.status(&user)),
            Op::Wait => Ok(self.settled(&user, request.wait_ms, false)),
            Op::Take => Ok(self.settled(&user, request.wait_ms, true)),
            Op::Verify => self.verify(&user),
            Op::Enroll => self.enroll(&user, request.add),
            Op::Delete => self.delete(&user),
            Op::List => self.list(&user),
        };
        match reply {
            Ok(mut reply) => {
                reply.device = Some(self.config.device.clone());
                reply
            }
            Err(message) => Reply::error(message),
        }
    }

    /// Returns the stored result of `user`. Drops it after the TTL.
    fn current<'a>(
        &self,
        results: &'a mut HashMap<String, Stored>,
        user: &str,
    ) -> Option<&'a ScanResult> {
        let expired = results
            .get(user)
            .and_then(|stored| stored.finished)
            .is_some_and(|finished| finished.elapsed() > self.config.result_ttl);
        if expired {
            results.remove(user);
        }
        results.get(user).map(|stored| &stored.result)
    }

    fn load_model(&self, user: &str) -> Result<Option<Vec<model::Encoding>>, String> {
        model::load(&self.config.state_dir, user).map_err(|error| {
            eprintln!("cannot read the model of {user}: {error}");
            "cannot read the face model".to_owned()
        })
    }

    fn stop_distance(&self, user: &str) -> f64 {
        let policy = Policy::load(&self.config.policy).unwrap_or_else(|error| {
            eprintln!("{error}. Using the built-in policy.");
            Policy::default()
        });
        policy.strictest_match_distance(user)
    }

    fn start_scan(self: &Arc<Self>, user: &str) -> Result<Reply, String> {
        let model = {
            let mut results = lock(&self.results);
            if matches!(self.current(&mut results, user), Some(ScanResult::Scanning)) {
                return Ok(Reply {
                    started: Some(false),
                    result: Some(ScanResult::Scanning),
                    ..Reply::default()
                });
            }
            let Some(model) = self.load_model(user)? else {
                results.insert(
                    user.to_owned(),
                    Stored {
                        result: ScanResult::NoModel,
                        finished: Some(Instant::now()),
                    },
                );
                drop(results);
                self.changed.notify_all();
                eprintln!("scan for {user}: no-model");
                return Ok(Reply {
                    started: Some(false),
                    result: Some(ScanResult::NoModel),
                    ..Reply::default()
                });
            };
            results.insert(
                user.to_owned(),
                Stored {
                    result: ScanResult::Scanning,
                    finished: None,
                },
            );
            model
        };
        let service = Arc::clone(self);
        let owner = user.to_owned();
        thread::spawn(move || service.run_scan(&owner, &model));
        Ok(Reply {
            started: Some(true),
            result: Some(ScanResult::Scanning),
            ..Reply::default()
        })
    }

    fn scan_now(&self, user: &str, model: &[model::Encoding]) -> Result<Scan, String> {
        let stop_at = self.stop_distance(user);
        lock(&self.scanner).scan(model, stop_at)
    }

    fn run_scan(&self, user: &str, model: &[model::Encoding]) {
        let result = match self.scan_now(user, model) {
            Ok(Scan { best, faces }) => ScanResult::Finished { best, faces },
            Err(error) => {
                // A failed scan counts as a scan without a face.
                eprintln!("scan for {user} failed: {error}");
                ScanResult::Finished {
                    best: None,
                    faces: 0,
                }
            }
        };
        eprintln!("scan for {user}: {}", describe(&result));
        lock(&self.results).insert(
            user.to_owned(),
            Stored {
                result,
                finished: Some(Instant::now()),
            },
        );
        self.changed.notify_all();
    }

    fn status(&self, user: &str) -> Reply {
        let mut results = lock(&self.results);
        Reply {
            result: self.current(&mut results, user).cloned(),
            ..Reply::default()
        }
    }

    /// Waits for a running scan, then returns the stored result. With
    /// `consume`, removes a finished result.
    fn settled(&self, user: &str, wait_ms: Option<u64>, consume: bool) -> Reply {
        let limit = wait_ms
            .map(Duration::from_millis)
            .map_or(self.config.settle_limit, |wait| {
                wait.min(self.config.settle_limit)
            });
        let deadline = Instant::now() + limit;
        let mut results = lock(&self.results);
        loop {
            let scanning = matches!(self.current(&mut results, user), Some(ScanResult::Scanning));
            let now = Instant::now();
            if !scanning || now >= deadline {
                break;
            }
            results = self
                .changed
                .wait_timeout(results, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let result = self.current(&mut results, user).cloned();
        if consume
            && matches!(
                result,
                Some(ScanResult::Finished { .. } | ScanResult::NoModel)
            )
        {
            results.remove(user);
        }
        Reply {
            result,
            ..Reply::default()
        }
    }

    fn verify(&self, user: &str) -> Result<Reply, String> {
        let result = match self.load_model(user)? {
            None => ScanResult::NoModel,
            Some(model) => {
                let Scan { best, faces } = self.scan_now(user, &model).map_err(|error| {
                    eprintln!("verify for {user} failed: {error}");
                    format!("scan failed: {error}")
                })?;
                ScanResult::Finished { best, faces }
            }
        };
        eprintln!("verify for {user}: {}", describe(&result));
        Ok(Reply {
            result: Some(result),
            ..Reply::default()
        })
    }

    fn enroll(&self, user: &str, add: bool) -> Result<Reply, String> {
        let samples = lock(&self.scanner).enroll().inspect_err(|error| {
            eprintln!("enroll for {user} failed: {error}");
        })?;
        let samples = if add {
            model::merge(self.load_model(user)?.unwrap_or_default(), samples)
        } else {
            samples
        };
        let count = samples.len();
        model::store(&self.config.state_dir, user, samples).map_err(|error| {
            eprintln!("cannot write the model of {user}: {error}");
            "cannot write the face model".to_owned()
        })?;
        eprintln!("enroll for {user}: {count} samples");
        Ok(Reply {
            samples: Some(count),
            ..Reply::default()
        })
    }

    fn delete(&self, user: &str) -> Result<Reply, String> {
        let deleted = model::remove(&self.config.state_dir, user).map_err(|error| {
            eprintln!("cannot delete the model of {user}: {error}");
            "cannot delete the face model".to_owned()
        })?;
        lock(&self.results).remove(user);
        Ok(Reply {
            deleted: Some(deleted),
            ..Reply::default()
        })
    }

    fn list(&self, user: &str) -> Result<Reply, String> {
        let samples = self.load_model(user)?.map_or(0, |model| model.len());
        Ok(Reply {
            samples: Some(samples),
            ..Reply::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use pam_biometrics_face::ENCODING_LENGTH;

    use super::*;

    const ROOT: u32 = 0;
    const ALICE: u32 = 1000;
    const BOB: u32 = 1001;
    const GREETER: u32 = 900;

    struct Users;

    impl UserDb for Users {
        fn lookup(&self, name: &str) -> Option<(String, u32)> {
            match name {
                "alice" => Some(("alice".to_owned(), ALICE)),
                "bob" => Some(("bob".to_owned(), BOB)),
                "greeter" => Some(("greeter".to_owned(), GREETER)),
                _ => None,
            }
        }
    }

    /// Returns queued scan results. A scan waits for a message on `gate`
    /// if the test sets one.
    struct FakeScanner {
        scans: Vec<Scan>,
        enrollments: Vec<Result<Vec<model::Encoding>, String>>,
        gate: Option<mpsc::Receiver<()>>,
        stops: Arc<Mutex<Vec<f64>>>,
    }

    impl Scanner for FakeScanner {
        fn scan(&mut self, _model: &[model::Encoding], stop_at: f64) -> Result<Scan, String> {
            if let Some(gate) = &self.gate {
                gate.recv().map_err(|error| error.to_string())?;
            }
            lock(&self.stops).push(stop_at);
            Ok(self.scans.remove(0))
        }

        fn enroll(&mut self) -> Result<Vec<model::Encoding>, String> {
            self.enrollments.remove(0)
        }
    }

    struct Fixture {
        service: Arc<Service<FakeScanner>>,
        dir: PathBuf,
        stops: Arc<Mutex<Vec<f64>>>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture(name: &str, scans: Vec<Scan>, gate: Option<mpsc::Receiver<()>>) -> Fixture {
        let dir = std::env::temp_dir().join(format!(
            "pam-biometricsd-service-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("policy.json"),
            r#"{"version": 1, "services": {"sudo": {"face": {"match_distance": 0.3}}}}"#,
        )
        .unwrap();
        let stops = Arc::new(Mutex::new(Vec::new()));
        let scanner = FakeScanner {
            scans,
            enrollments: vec![
                Ok(vec![vec![0.1; ENCODING_LENGTH]; 10]),
                Ok(vec![vec![0.2; ENCODING_LENGTH]; 10]),
                Ok(vec![vec![0.3; ENCODING_LENGTH]; 10]),
                Ok(vec![vec![0.4; ENCODING_LENGTH]; 10]),
                Err("0 frames had exactly one face, enrollment needs 3".to_owned()),
            ],
            gate,
            stops: Arc::clone(&stops),
        };
        let config = Config {
            state_dir: dir.clone(),
            device: "/dev/video9".to_owned(),
            policy: dir.join("policy.json"),
            result_ttl: Duration::from_secs(120),
            settle_limit: Duration::from_secs(5),
            greeter_uid: Some(GREETER),
        };
        Fixture {
            service: Service::new(config, Box::new(Users), scanner),
            dir,
            stops,
        }
    }

    fn request(op: Op, user: &str) -> Request {
        Request::new(op, user)
    }

    fn enroll_alice(fixture: &Fixture) {
        let reply = fixture.service.handle(ALICE, &request(Op::Enroll, "alice"));
        assert_eq!(reply.samples, Some(10), "{reply:?}");
    }

    const MATCH: Scan = Scan {
        best: Some(0.25),
        faces: 2,
    };

    #[test]
    fn authorization() {
        let fixture = fixture("auth", vec![], None);
        let service = &fixture.service;
        let denied = Some("permission denied".to_owned());
        assert_eq!(
            service.handle(BOB, &request(Op::List, "alice")).error,
            denied
        );
        assert_eq!(
            service.handle(BOB, &request(Op::Scan, "alice")).error,
            denied
        );
        assert_eq!(
            service.handle(GREETER, &request(Op::Status, "alice")).error,
            denied
        );
        assert_eq!(
            service.handle(GREETER, &request(Op::Take, "alice")).error,
            denied
        );
        assert_eq!(
            service.handle(GREETER, &request(Op::Enroll, "alice")).error,
            denied
        );
        assert_eq!(
            service.handle(ALICE, &request(Op::List, "alice")).error,
            None
        );
        assert_eq!(service.handle(ROOT, &request(Op::List, "bob")).error, None);
        // The greeter can start a scan for any user. Alice has no model.
        let reply = service.handle(GREETER, &request(Op::Scan, "alice"));
        assert_eq!(reply.error, None);
        assert_eq!(reply.result, Some(ScanResult::NoModel));
        assert_eq!(
            service.handle(ROOT, &request(Op::List, "nobody")).error,
            Some("unknown user".to_owned())
        );
    }

    #[test]
    fn replies_include_the_device() {
        let fixture = fixture("device", vec![], None);
        let reply = fixture.service.handle(ALICE, &request(Op::Status, "alice"));
        assert_eq!(reply.device.as_deref(), Some("/dev/video9"));
        assert_eq!(reply.result, None);
    }

    #[test]
    fn scan_without_model() {
        let fixture = fixture("no-model", vec![], None);
        let service = &fixture.service;
        let reply = service.handle(ALICE, &request(Op::Scan, "alice"));
        assert_eq!(reply.started, Some(false));
        let reply = service.handle(ROOT, &request(Op::Take, "alice"));
        assert_eq!(reply.result, Some(ScanResult::NoModel));
        let reply = service.handle(ROOT, &request(Op::Take, "alice"));
        assert_eq!(reply.result, None);
    }

    #[test]
    fn scan_then_take_consumes_the_result() {
        let (open, gate) = mpsc::channel();
        let fixture = fixture("take", vec![MATCH], Some(gate));
        let service = &fixture.service;
        enroll_alice(&fixture);

        let reply = service.handle(ALICE, &request(Op::Scan, "alice"));
        assert_eq!(reply.started, Some(true));
        let again = service.handle(ALICE, &request(Op::Scan, "alice"));
        assert_eq!(again.started, Some(false));
        assert_eq!(
            service.handle(ALICE, &request(Op::Status, "alice")).result,
            Some(ScanResult::Scanning)
        );

        // A bounded take returns the running state without consuming it.
        let mut quick = request(Op::Take, "alice");
        quick.wait_ms = Some(10);
        assert_eq!(
            service.handle(ROOT, &quick).result,
            Some(ScanResult::Scanning)
        );

        open.send(()).unwrap();
        let finished = Some(ScanResult::Finished {
            best: Some(0.25),
            faces: 2,
        });
        assert_eq!(
            service.handle(ALICE, &request(Op::Wait, "alice")).result,
            finished
        );
        // wait and status do not consume.
        assert_eq!(
            service.handle(ALICE, &request(Op::Status, "alice")).result,
            finished
        );
        assert_eq!(
            service.handle(ROOT, &request(Op::Take, "alice")).result,
            finished
        );
        assert_eq!(
            service.handle(ROOT, &request(Op::Take, "alice")).result,
            None
        );
        // The policy lists sudo with 0.3. The defaults have 0.45.
        assert_eq!(*lock(&fixture.stops), [0.3]);
    }

    #[test]
    fn results_expire() {
        let mut fixture = fixture("ttl", vec![MATCH], None);
        Arc::get_mut(&mut fixture.service)
            .unwrap()
            .config
            .result_ttl = Duration::ZERO;
        enroll_alice(&fixture);
        let service = &fixture.service;
        service.handle(ALICE, &request(Op::Scan, "alice"));
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            service.handle(ALICE, &request(Op::Wait, "alice")).result,
            None
        );
    }

    #[test]
    fn verify_does_not_store() {
        let fixture = fixture("verify", vec![MATCH], None);
        let service = &fixture.service;
        assert_eq!(
            service.handle(ALICE, &request(Op::Verify, "alice")).result,
            Some(ScanResult::NoModel)
        );
        enroll_alice(&fixture);
        assert_eq!(
            service.handle(ALICE, &request(Op::Verify, "alice")).result,
            Some(ScanResult::Finished {
                best: Some(0.25),
                faces: 2
            })
        );
        assert_eq!(
            service.handle(ALICE, &request(Op::Status, "alice")).result,
            None
        );
    }

    #[test]
    fn enroll_replace_add_delete_list() {
        let fixture = fixture("enroll", vec![], None);
        let service = &fixture.service;
        let list = || service.handle(ALICE, &request(Op::List, "alice")).samples;
        assert_eq!(list(), Some(0));
        enroll_alice(&fixture);
        assert_eq!(list(), Some(10));
        // A plain enroll replaces the model.
        enroll_alice(&fixture);
        let model = model::load(&fixture.dir, "alice").unwrap().unwrap();
        assert!(
            model
                .iter()
                .all(|sample| (sample[0] - 0.2).abs() < f64::EPSILON)
        );

        let mut add = request(Op::Enroll, "alice");
        add.add = true;
        assert_eq!(service.handle(ALICE, &add).samples, Some(20));
        assert_eq!(service.handle(ALICE, &add).samples, Some(30));
        let model = model::load(&fixture.dir, "alice").unwrap().unwrap();
        assert!((model[0][0] - 0.2).abs() < f64::EPSILON);
        assert!((model[29][0] - 0.4).abs() < f64::EPSILON);

        let failed = service.handle(ALICE, &add);
        assert_eq!(
            failed.error.as_deref(),
            Some("0 frames had exactly one face, enrollment needs 3")
        );
        assert_eq!(list(), Some(30));

        assert_eq!(
            service.handle(ALICE, &request(Op::Delete, "alice")).deleted,
            Some(true)
        );
        assert_eq!(
            service.handle(ALICE, &request(Op::Delete, "alice")).deleted,
            Some(false)
        );
        assert_eq!(list(), Some(0));
    }
}
