//! The export formats plaso has no samples of, written for these tests
//! after the providers' documented formats (`tests/fixtures/written/`):
//! every record's main fields as Python's own JSON and CSV modules read
//! them (`tests/oracle/written.tsv`, written by `tests/oracle/gen.py`).

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

#[test]
fn every_record_as_python_reads_it() {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/written");
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n != "NOTICE")
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
    let expected: Vec<&str> = include_str!("oracle/written.tsv").lines().collect();
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
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
}
