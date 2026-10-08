//! plaso's cloud log samples (Apache-2.0, `tests/fixtures/plaso/`,
//! gzip-compressed): every record plaso reads, read the same
//! (`tests/oracle/plaso.tsv`, written from plaso's own output, see
//! `tests/oracle/README`).

use std::io::Read;

use cloudlogs::{Event, Source};

fn gunzip(compressed: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed)
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn get(event: &Event, path: &str) -> String {
    event.get(path).unwrap_or_default().to_owned()
}

fn some(value: Option<&String>) -> String {
    value.cloned().unwrap_or_default()
}

/// An event as the oracle's fields.
fn line(name: &str, e: &Event) -> String {
    let micros = e
        .time
        .and_then(|t| t.ticks())
        .map_or_else(String::new, |t| (t / 10).to_string());
    let fields = match e.source.unwrap() {
        Source::CloudTrail => vec![
            some(e.operation.as_ref()),
            some(e.service.as_ref()),
            // plaso's user name: lookup-events' Username, or the record's.
            e.get("Username")
                .or_else(|| e.get("userIdentity.userName"))
                .unwrap_or_default()
                .to_owned(),
            some(e.actor_id.as_ref()),
            some(e.source_ip.as_ref()),
            some(e.target.as_ref()),
            get(e, "userIdentity.accessKeyId"),
        ],
        Source::Microsoft365 => vec![
            some(e.operation.as_ref()),
            some(e.service.as_ref()),
            some(e.actor.as_ref()),
            some(e.actor_id.as_ref()),
            some(e.source_ip.as_ref()),
            some(e.target.as_ref()),
            some(e.result.as_ref()),
            some(e.id.as_ref()),
            get(e, "RecordType"),
            get(e, "UserType"),
            get(e, "OrganizationId"),
        ],
        Source::AzureActivity => vec![
            some(e.operation.as_ref()),
            some(e.service.as_ref()),
            some(e.actor.as_ref()),
            some(e.source_ip.as_ref()),
            some(e.target.as_ref()),
            some(e.id.as_ref()),
            get(e, "level"),
            get(e, "correlation_id"),
            get(e, "resource_group_name"),
            get(e, "resource_type.value"),
            get(e, "subscription_id"),
            get(e, "tenant_id"),
            get(e, "event_name.value"),
        ],
        Source::GoogleCloud => vec![
            get(e, "protoPayload.methodName"),
            some(e.service.as_ref()),
            get(e, "protoPayload.authenticationInfo.principalEmail"),
            get(e, "jsonPayload.actor.user"),
            some(e.source_ip.as_ref()),
            some(e.user_agent.as_ref()),
            some(e.target.as_ref()),
            get(e, "protoPayload.status.message"),
            get(e, "logName"),
            get(e, "severity"),
            get(e, "textPayload"),
            some(e.operation.as_ref()),
        ],
        other => panic!("{other:?} in plaso's samples"),
    };
    [vec![name.to_owned(), micros], fields].concat().join("\t")
}

#[test]
fn every_record_as_plaso_reads_it() {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/plaso");
    let mut got = Vec::new();
    for name in [
        "aws_cloudtrail.jsonl",
        "azure_activity_log.jsonl",
        "gcp_logging.jsonl",
        "microsoft_audit_log.jsonl",
    ] {
        let data = gunzip(&std::fs::read(format!("{folder}/{name}.gz")).unwrap());
        assert!(cloudlogs::detect(&data).is_some(), "{name}");
        let log = cloudlogs::read(&data);
        assert_eq!(log.problems, Vec::<String>::new(), "{name}");
        got.extend(log.events.iter().map(|e| line(name, e)));
    }
    got.sort();
    let mut expected: Vec<&str> = include_str!("oracle/plaso.tsv").lines().collect();
    expected.sort_unstable();
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
}
