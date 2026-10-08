//! The export formats plaso has no samples of, written for these tests
//! after the providers' documented formats (`tests/fixtures/written/`):
//! every record's main fields as Python's own JSON and CSV modules read
//! them (`tests/oracle/written.tsv`, written by `tests/oracle/gen.py`); and
//! open Google Workspace samples, the same way.

use cloudlogs::Event;

fn line(name: &str, event: &Event) -> String {
    let main = [
        &event.operation,
        &event.service,
        &event.actor,
        &event.actor_id,
        &event.source_ip,
        &event.user_agent,
        &event.target,
        &event.result,
        &event.id,
        &event.location,
    ]
    .map(|value| value.clone().unwrap_or_default());
    [
        vec![
            name.to_owned(),
            event.position.to_string(),
            event.source.unwrap().name().to_owned(),
            event.time.and_then(|t| t.to_iso8601()).unwrap_or_default(),
        ],
        main.to_vec(),
    ]
    .concat()
    .join("\t")
}

/// Every file of `folder` read, its events as lines.
fn read_folder(folder: &str) -> Vec<String> {
    let folder = format!("{}/tests/fixtures/{folder}", env!("CARGO_MANIFEST_DIR"));
    let mut names: Vec<String> = std::fs::read_dir(&folder)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n != "NOTICE" && n != "LICENSE")
        .collect();
    names.sort();
    let mut got = Vec::new();
    for name in &names {
        let data = std::fs::read(format!("{folder}/{name}")).unwrap();
        assert!(cloudlogs::detect(&data).is_some(), "{name}");
        let log = cloudlogs::read(&data);
        assert_eq!(log.problems, Vec::<String>::new(), "{name}");
        got.extend(log.events.iter().map(|e| line(name, e)));
    }
    got
}

fn assert_same(got: &[String], oracle: &str) {
    let expected: Vec<&str> = oracle.lines().collect();
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
}

#[test]
fn every_record_as_python_reads_it() {
    assert_same(&read_folder("written"), include_str!("oracle/written.tsv"));
}

/// Google Workspace activities from Splunk's `attack_data` (Apache-2.0,
/// `tests/fixtures/attack_data/`, see its NOTICE).
#[test]
fn workspace_samples_as_python_reads_them() {
    assert_same(
        &read_folder("attack_data"),
        include_str!("oracle/attack_data.tsv"),
    );
}

#[test]
fn every_value_is_kept() {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/written");
    let log = cloudlogs::read(&std::fs::read(format!("{folder}/m365-purview.csv")).unwrap());
    let rule = &log.events[0];
    assert_eq!(rule.get("Parameters.1.Value"), Some("invoice;payment"));
    let log = cloudlogs::read(&std::fs::read(format!("{folder}/cloudtrail-s3.json")).unwrap());
    assert_eq!(
        log.events[2].get("responseElements.accessKey.accessKeyId"),
        Some("AKIAEXAMPLENEW")
    );
    let log = cloudlogs::read(&std::fs::read(format!("{folder}/workspace-reports.json")).unwrap());
    let token = &log.events[2];
    assert_eq!(
        token.get("event.parameters.scope"),
        Some("https://mail.google.com/, https://www.googleapis.com/auth/drive")
    );
    assert_eq!(
        token.get("event.parameters.client_id"),
        Some("123456.apps.googleusercontent.com")
    );
}
