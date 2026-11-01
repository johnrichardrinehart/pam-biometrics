use std::collections::BTreeMap;

use crate::{
    Combine, Error, FaceClass, FaceSettings, Factor, OnNoDecision, Outcome, Policy, Settings,
    StepOutcome,
};

fn parse(text: &str) -> Result<Policy, Error> {
    Policy::parse(text, "test")
}

fn error(text: &str) -> String {
    parse(text).expect_err("policy must be invalid").to_string()
}

#[test]
fn built_in_defaults() {
    let settings = Policy::default().resolve(None, None);
    assert_eq!(settings.factors, [Factor::Fingerprint, Factor::Face]);
    assert_eq!(settings.combine, Combine::Any);
    assert_eq!(settings.on_no_decision, OnNoDecision::Allow);
    assert_eq!(settings.timeout_seconds, 15);
    assert_eq!(settings.password_prompt, None);
    assert_eq!(settings.finish_prompt, None);
    assert_eq!(settings.fingerprint.max_tries, 3);
    assert!((settings.face.match_distance - 0.45).abs() < f64::EPSILON);
    assert!((settings.face.reject_distance - 0.6).abs() < f64::EPSILON);
    assert_eq!(settings.face.min_reject_frames, 3);
    assert_eq!(settings.face.trigger, "");
}

#[test]
fn minimal_document_gives_built_in_defaults() {
    let policy = parse(r#"{"version": 1}"#).unwrap();
    assert_eq!(
        policy.resolve(Some("sudo"), Some("alice")),
        Settings::default()
    );
}

const LAYERED: &str = r#"{
  "version": 1,
  "defaults": { "timeout_seconds": 2 },
  "services": { "sudo": { "timeout_seconds": 3 } },
  "users": {
    "alice": {
      "defaults": { "timeout_seconds": 4 },
      "services": { "sudo": { "timeout_seconds": 5 } }
    }
  }
}"#;

#[test]
fn resolution_order() {
    let policy = parse(LAYERED).unwrap();
    let timeout = |service, user| policy.resolve(service, user).timeout_seconds;
    assert_eq!(timeout(None, None), 2);
    assert_eq!(timeout(Some("login"), None), 2);
    assert_eq!(timeout(Some("sudo"), None), 3);
    assert_eq!(timeout(Some("sudo"), Some("bob")), 3);
    assert_eq!(timeout(None, Some("alice")), 4);
    assert_eq!(timeout(Some("login"), Some("alice")), 4);
    assert_eq!(timeout(Some("sudo"), Some("alice")), 5);
}

#[test]
fn user_service_layer_does_not_apply_to_other_users() {
    let policy = parse(
        r#"{"version": 1, "users": {"alice": {"services": {"sudo": {"on_no_decision": "deny"}}}}}"#,
    )
    .unwrap();
    assert_eq!(
        policy.resolve(Some("sudo"), Some("alice")).on_no_decision,
        OnNoDecision::Deny
    );
    assert_eq!(
        policy.resolve(Some("sudo"), Some("bob")).on_no_decision,
        OnNoDecision::Allow
    );
    assert_eq!(
        policy.resolve(Some("login"), Some("alice")).on_no_decision,
        OnNoDecision::Allow
    );
}

#[test]
fn lists_replace() {
    let policy = parse(
        r#"{"version": 1, "defaults": {"factors": ["face"]}, "services": {"sudo": {"factors": ["fingerprint"]}}}"#,
    )
    .unwrap();
    assert_eq!(policy.resolve(None, None).factors, [Factor::Face]);
    assert_eq!(
        policy.resolve(Some("sudo"), None).factors,
        [Factor::Fingerprint]
    );
}

#[test]
fn objects_merge() {
    let policy = parse(
        r#"{
          "version": 1,
          "defaults": { "face": { "reject_distance": 0.7, "min_reject_frames": 5 } },
          "users": { "alice": { "defaults": { "face": { "match_distance": 0.4 } } } }
        }"#,
    )
    .unwrap();
    let face = policy.resolve(None, Some("alice")).face;
    assert!((face.match_distance - 0.4).abs() < f64::EPSILON);
    assert!((face.reject_distance - 0.7).abs() < f64::EPSILON);
    assert_eq!(face.min_reject_frames, 5);
}

#[test]
fn prompts_and_trigger_resolve() {
    let policy = parse(
        r#"{
          "version": 1,
          "defaults": { "password_prompt": "Password or Enter: " },
          "services": {
            "greetd": { "finish_prompt": "Press Enter.", "face": { "trigger": "f" } }
          },
          "users": { "alice": { "services": { "greetd": { "face": { "trigger": "" } } } } }
        }"#,
    )
    .unwrap();
    let sudo = policy.resolve(Some("sudo"), None);
    assert_eq!(sudo.password_prompt.as_deref(), Some("Password or Enter: "));
    assert_eq!(sudo.finish_prompt, None);
    assert_eq!(sudo.face.trigger, "");
    let greetd = policy.resolve(Some("greetd"), Some("bob"));
    assert_eq!(
        greetd.password_prompt.as_deref(),
        Some("Password or Enter: ")
    );
    assert_eq!(greetd.finish_prompt.as_deref(), Some("Press Enter."));
    assert_eq!(greetd.face.trigger, "f");
    // The trigger merges like the other face fields.
    assert!((greetd.face.match_distance - 0.45).abs() < f64::EPSILON);
    assert_eq!(
        policy.resolve(Some("greetd"), Some("alice")).face.trigger,
        ""
    );
}

#[test]
fn unknown_fields_are_errors() {
    for text in [
        r#"{"version": 1, "extra": true}"#,
        r#"{"version": 1, "defaults": {"factor": ["face"]}}"#,
        r#"{"version": 1, "defaults": {"face": {"tolerance": 0.5}}}"#,
        r#"{"version": 1, "defaults": {"fingerprint": {"tries": 2}}}"#,
        r#"{"version": 1, "services": {"sudo": {"timeout": 2}}}"#,
        r#"{"version": 1, "users": {"alice": {"service": {}}}}"#,
        r#"{"version": 1, "defaults": {"factors": ["iris"]}}"#,
        r#"{"version": 1, "defaults": {"combine": "first"}}"#,
        r#"{"version": 1, "defaults": {"on_no_decision": "ignore"}}"#,
        // `finish_prompt` replaced `prompt`.
        r#"{"version": 1, "defaults": {"prompt": "Touch the reader."}}"#,
        r#"{"version": 1, "defaults": {"face": {"trigger": null}}}"#,
    ] {
        assert!(
            matches!(parse(text), Err(Error::Parse { .. })),
            "accepted {text}"
        );
    }
}

#[test]
fn null_is_an_error() {
    assert!(matches!(
        parse(r#"{"version": 1, "defaults": {"factors": null}}"#),
        Err(Error::Parse { .. })
    ));
    assert!(matches!(
        parse(r#"{"version": 1, "defaults": {"face": {"match_distance": null}}}"#),
        Err(Error::Parse { .. })
    ));
}

#[test]
fn version_is_required_and_checked() {
    assert!(matches!(parse("{}"), Err(Error::Parse { .. })));
    assert_eq!(
        error(r#"{"version": 2}"#),
        "test: version: must be 1, not 2"
    );
}

#[test]
fn layer_values_are_checked() {
    for (text, message) in [
        (
            r#"{"version": 1, "defaults": {"factors": ["face", "face"]}}"#,
            "test: defaults: factors lists face more than once",
        ),
        (
            r#"{"version": 1, "services": {"sudo": {"timeout_seconds": 0}}}"#,
            "test: services.sudo: timeout_seconds must be at least 1",
        ),
        (
            r#"{"version": 1, "defaults": {"password_prompt": "  "}}"#,
            "test: defaults: password_prompt must contain text",
        ),
        (
            r#"{"version": 1, "services": {"sudo": {"finish_prompt": ""}}}"#,
            "test: services.sudo: finish_prompt must contain text",
        ),
        (
            r#"{"version": 1, "defaults": {"finish_prompt": "Touch\nthe reader: "}}"#,
            "test: defaults: finish_prompt must not contain control characters",
        ),
        (
            r#"{"version": 1, "defaults": {"face": {"trigger": "f\r"}}}"#,
            "test: defaults: face.trigger must not contain control characters",
        ),
        (
            r#"{"version": 1, "users": {"alice": {"defaults": {"fingerprint": {"max_tries": 0}}}}}"#,
            "test: users.alice.defaults: fingerprint.max_tries must be at least 1",
        ),
        (
            r#"{"version": 1, "defaults": {"face": {"match_distance": 0}}}"#,
            "test: defaults: face.match_distance must be greater than 0",
        ),
        (
            r#"{"version": 1, "defaults": {"face": {"reject_distance": -0.5}}}"#,
            "test: defaults: face.reject_distance must be greater than 0",
        ),
        (
            r#"{"version": 1, "users": {"alice": {"services": {"sudo": {"face": {"min_reject_frames": 0}}}}}}"#,
            "test: users.alice.services.sudo: face.min_reject_frames must be at least 1",
        ),
    ] {
        assert_eq!(error(text), message);
    }
}

#[test]
fn negative_numbers_do_not_parse_as_counts() {
    assert!(matches!(
        parse(r#"{"version": 1, "defaults": {"timeout_seconds": -1}}"#),
        Err(Error::Parse { .. })
    ));
}

#[test]
fn resolved_thresholds_are_checked() {
    assert_eq!(
        error(r#"{"version": 1, "defaults": {"face": {"match_distance": 0.7}}}"#),
        "test: resolved settings: face.match_distance (0.7) is greater than face.reject_distance (0.6)"
    );
    // Each layer is valid alone. The combination for alice and sudo is not.
    assert_eq!(
        error(
            r#"{
              "version": 1,
              "services": { "sudo": { "face": { "reject_distance": 0.5 } } },
              "users": { "alice": { "defaults": { "face": { "match_distance": 0.55, "reject_distance": 0.65 } },
                                    "services": { "sudo": { "face": { "reject_distance": 0.5 } } } } }
            }"#
        ),
        "test: resolved settings for service sudo and user alice: face.match_distance (0.55) is greater than face.reject_distance (0.5)"
    );
    // Equal thresholds leave no uncertain band. That is valid.
    parse(
        r#"{"version": 1, "defaults": {"face": {"match_distance": 0.5, "reject_distance": 0.5}}}"#,
    )
    .unwrap();
}

#[test]
fn load_missing_file_gives_defaults() {
    let path = std::env::temp_dir().join(format!(
        "pam-biometrics-policy-missing-{}.json",
        std::process::id()
    ));
    assert_eq!(Policy::load(&path).unwrap(), Policy::default());
}

#[test]
fn load_reads_file() {
    let path = std::env::temp_dir().join(format!(
        "pam-biometrics-policy-load-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, LAYERED).unwrap();
    let loaded = Policy::load(&path);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        loaded
            .unwrap()
            .resolve(Some("sudo"), Some("alice"))
            .timeout_seconds,
        5
    );
}

#[test]
fn load_reports_path_in_errors() {
    let path = std::env::temp_dir().join(format!(
        "pam-biometrics-policy-invalid-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, r#"{"version": 3}"#).unwrap();
    let loaded = Policy::load(&path);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        loaded.unwrap_err().to_string(),
        format!("{}: version: must be 1, not 3", path.display())
    );
}

#[test]
fn strictest_match_distance() {
    let policy = parse(
        r#"{
          "version": 1,
          "defaults": { "face": { "match_distance": 0.45 } },
          "services": {
            "sudo": { "face": { "match_distance": 0.35 } },
            "login": { "factors": ["fingerprint"], "face": { "match_distance": 0.2 } }
          },
          "users": {
            "alice": { "services": { "polkit-1": { "face": { "match_distance": 0.3 } } } },
            "bob": { "defaults": { "face": { "match_distance": 0.5, "reject_distance": 0.7 } } }
          }
        }"#,
    )
    .unwrap();
    // login has no face factor, so its distance does not count.
    assert!((policy.strictest_match_distance("alice") - 0.3).abs() < f64::EPSILON);
    assert!((policy.strictest_match_distance("bob") - 0.5).abs() < f64::EPSILON);
    assert!((policy.strictest_match_distance("carol") - 0.35).abs() < f64::EPSILON);

    let no_face = parse(r#"{"version": 1, "defaults": {"factors": []}}"#).unwrap();
    assert!((no_face.strictest_match_distance("alice") - 0.45).abs() < f64::EPSILON);
}

#[test]
fn serialized_settings_round_trip() {
    let settings = Settings::default();
    let text = serde_json::to_string(&settings).unwrap();
    assert_eq!(serde_json::from_str::<Settings>(&text).unwrap(), settings);
}

fn settings(factors: &[Factor], combine: Combine, on_no_decision: OnNoDecision) -> Settings {
    Settings {
        factors: factors.to_vec(),
        combine,
        on_no_decision,
        ..Settings::default()
    }
}

const BOTH: &[Factor] = &[Factor::Fingerprint, Factor::Face];

/// Decides with a fingerprint and a face outcome. `None` means "still running".
fn decide(
    combine: Combine,
    on_no_decision: OnNoDecision,
    fingerprint: Option<Outcome>,
    face: Option<Outcome>,
    deadline_passed: bool,
) -> Option<(Outcome, StepOutcome)> {
    let mut finished = BTreeMap::new();
    if let Some(outcome) = fingerprint {
        finished.insert(Factor::Fingerprint, outcome);
    }
    if let Some(outcome) = face {
        finished.insert(Factor::Face, outcome);
    }
    settings(BOTH, combine, on_no_decision)
        .decide(&finished, deadline_passed)
        .map(|verdict| (verdict.combined, verdict.outcome))
}

const M: Option<Outcome> = Some(Outcome::Match);
const R: Option<Outcome> = Some(Outcome::Reject);
const N: Option<Outcome> = Some(Outcome::NoDecision);
const P: Option<Outcome> = None;

const OUTCOMES: [Option<Outcome>; 4] = [M, R, N, P];

/// The expected combined outcome for two factors, or `None` to wait.
fn expected(
    combine: Combine,
    fingerprint: Option<Outcome>,
    face: Option<Outcome>,
    deadline_passed: bool,
) -> Option<Outcome> {
    use Outcome::{Match, NoDecision, Reject};
    let pair = (fingerprint, face);
    match combine {
        Combine::Any => match pair {
            (Some(Match), _) | (_, Some(Match)) => Some(Match),
            (None, _) | (_, None) if !deadline_passed => None,
            (Some(Reject), _) | (_, Some(Reject)) => Some(Reject),
            _ => Some(NoDecision),
        },
        Combine::All => match pair {
            (Some(Reject), _) | (_, Some(Reject)) => Some(Reject),
            (Some(Match), Some(Match)) => Some(Match),
            (None, _) | (_, None) if !deadline_passed => None,
            _ => Some(NoDecision),
        },
    }
}

#[test]
fn decision_table() {
    for combine in [Combine::Any, Combine::All] {
        for on_no_decision in [OnNoDecision::Allow, OnNoDecision::Deny] {
            for fingerprint in OUTCOMES {
                for face in OUTCOMES {
                    for deadline_passed in [false, true] {
                        let got =
                            decide(combine, on_no_decision, fingerprint, face, deadline_passed);
                        let want =
                            expected(combine, fingerprint, face, deadline_passed).map(|combined| {
                                let step = match (combined, on_no_decision) {
                                    (Outcome::Match, _) => StepOutcome::Success,
                                    (Outcome::NoDecision, OnNoDecision::Allow) => {
                                        StepOutcome::NoDecision
                                    }
                                    _ => StepOutcome::Reject,
                                };
                                (combined, step)
                            });
                        assert_eq!(
                            got, want,
                            "{combine:?} {on_no_decision:?} fingerprint={fingerprint:?} face={face:?} deadline={deadline_passed}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn any_first_match_wins_before_the_other_factor_ends() {
    assert_eq!(
        decide(Combine::Any, OnNoDecision::Deny, P, M, false),
        Some((Outcome::Match, StepOutcome::Success))
    );
    assert_eq!(
        decide(Combine::Any, OnNoDecision::Allow, R, M, false),
        Some((Outcome::Match, StepOutcome::Success))
    );
}

#[test]
fn any_reject_waits_for_a_possible_match() {
    assert_eq!(decide(Combine::Any, OnNoDecision::Allow, R, P, false), None);
    assert_eq!(
        decide(Combine::Any, OnNoDecision::Allow, R, P, true),
        Some((Outcome::Reject, StepOutcome::Reject))
    );
    assert_eq!(
        decide(Combine::Any, OnNoDecision::Allow, R, N, false),
        Some((Outcome::Reject, StepOutcome::Reject))
    );
}

#[test]
fn all_reject_wins_at_once() {
    assert_eq!(
        decide(Combine::All, OnNoDecision::Allow, P, R, false),
        Some((Outcome::Reject, StepOutcome::Reject))
    );
    assert_eq!(
        decide(Combine::All, OnNoDecision::Allow, M, R, false),
        Some((Outcome::Reject, StepOutcome::Reject))
    );
}

#[test]
fn all_needs_every_match() {
    assert_eq!(decide(Combine::All, OnNoDecision::Allow, M, P, false), None);
    assert_eq!(
        decide(Combine::All, OnNoDecision::Allow, M, M, false),
        Some((Outcome::Match, StepOutcome::Success))
    );
    assert_eq!(
        decide(Combine::All, OnNoDecision::Allow, M, P, true),
        Some((Outcome::NoDecision, StepOutcome::NoDecision))
    );
    assert_eq!(
        decide(Combine::All, OnNoDecision::Deny, M, N, false),
        Some((Outcome::NoDecision, StepOutcome::Reject))
    );
}

#[test]
fn no_decision_follows_on_no_decision() {
    assert_eq!(
        decide(Combine::Any, OnNoDecision::Allow, N, N, false),
        Some((Outcome::NoDecision, StepOutcome::NoDecision))
    );
    assert_eq!(
        decide(Combine::Any, OnNoDecision::Deny, N, N, false),
        Some((Outcome::NoDecision, StepOutcome::Reject))
    );
    assert_eq!(
        decide(Combine::Any, OnNoDecision::Deny, P, P, true),
        Some((Outcome::NoDecision, StepOutcome::Reject))
    );
}

#[test]
fn empty_factors_give_no_decision_at_once() {
    for combine in [Combine::Any, Combine::All] {
        for on_no_decision in [OnNoDecision::Allow, OnNoDecision::Deny] {
            let verdict = settings(&[], combine, on_no_decision)
                .decide(&BTreeMap::new(), false)
                .unwrap();
            assert_eq!(verdict.combined, Outcome::NoDecision);
            assert_eq!(verdict.outcome, StepOutcome::NoDecision);
        }
    }
}

#[test]
fn disabled_factors_do_not_count() {
    let face_only = settings(&[Factor::Face], Combine::All, OnNoDecision::Allow);
    let mut finished = BTreeMap::new();
    finished.insert(Factor::Fingerprint, Outcome::Reject);
    assert_eq!(face_only.decide(&finished, false), None);
    finished.insert(Factor::Face, Outcome::Match);
    assert_eq!(
        face_only
            .decide(&finished, false)
            .map(|verdict| verdict.outcome),
        Some(StepOutcome::Success)
    );
}

#[test]
fn exit_codes() {
    assert_eq!(StepOutcome::Success.exit_code(), 0);
    assert_eq!(StepOutcome::Reject.exit_code(), 10);
    assert_eq!(StepOutcome::NoDecision.exit_code(), 20);
}

#[test]
fn face_classification_boundaries() {
    let face = FaceSettings {
        match_distance: 0.4,
        reject_distance: 0.6,
        min_reject_frames: 3,
        trigger: String::new(),
    };
    assert_eq!(face.classify(Some(0.0), 1), FaceClass::Match);
    assert_eq!(face.classify(Some(0.4), 1), FaceClass::Match);
    assert_eq!(face.classify(Some(0.400_001), 1), FaceClass::Uncertain);
    assert_eq!(face.classify(Some(0.6), 10), FaceClass::Uncertain);
    assert_eq!(face.classify(Some(0.600_001), 3), FaceClass::Reject);
    assert_eq!(face.classify(Some(0.600_001), 2), FaceClass::Absent);
    assert_eq!(face.classify(Some(0.9), 0), FaceClass::Absent);
    assert_eq!(face.classify(None, 0), FaceClass::Absent);
    assert_eq!(face.classify(None, 5), FaceClass::Absent);

    assert_eq!(FaceClass::Match.outcome(), Outcome::Match);
    assert_eq!(FaceClass::Reject.outcome(), Outcome::Reject);
    assert_eq!(FaceClass::Uncertain.outcome(), Outcome::NoDecision);
    assert_eq!(FaceClass::Absent.outcome(), Outcome::NoDecision);
}

#[test]
fn equal_thresholds_have_no_uncertain_band() {
    let face = FaceSettings {
        match_distance: 0.5,
        reject_distance: 0.5,
        min_reject_frames: 1,
        trigger: String::new(),
    };
    assert_eq!(face.classify(Some(0.5), 1), FaceClass::Match);
    assert_eq!(face.classify(Some(0.500_001), 1), FaceClass::Reject);
}
