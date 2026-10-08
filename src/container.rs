//! The containers records come in: a JSON document (an array, an object
//! holding them, or one record), JSON lines, or a CSV export whose
//! `AuditData` column holds each record's JSON.

use common::json::{self, Json};

use crate::csv;

/// Members that hold a document's records.
const HOLDERS: [&str; 5] = ["Records", "records", "value", "Events", "items"];

/// The records of `data`, each with its position (a line, a CSV row or an
/// element, from 1). With `head`, `data` may end mid-record: what can't be
/// read is dropped silently.
pub(crate) fn records(data: &[u8], head: bool, problems: &mut Vec<String>) -> Vec<(usize, Json)> {
    let text = String::from_utf8_lossy(data);
    let text = text.trim_start_matches('\u{feff}').trim_start();
    if text.starts_with('[') || text.starts_with('{') {
        if let Ok(document) = json::parse(text) {
            return elements(document);
        }
        return lines(text, head, problems);
    }
    if text
        .lines()
        .next()
        .is_some_and(|header| header.contains("AuditData"))
    {
        return audit_data(text, head, problems);
    }
    if !head && !text.is_empty() {
        problems.push("neither JSON, JSON lines nor a CSV with an AuditData column".to_owned());
    }
    Vec::new()
}

/// A document's records: an array's elements, the array a holder member
/// names, or the document itself.
fn elements(document: Json) -> Vec<(usize, Json)> {
    let holder = HOLDERS.iter().find_map(|name| {
        document
            .get(name)
            .and_then(Json::as_array)
            .map(<[Json]>::to_vec)
    });
    match (document, holder) {
        (_, Some(items)) | (Json::Array(items), None) => (1..).zip(items).collect(),
        (record, None) => vec![(1, record)],
    }
}

/// JSON lines: one record per line; a line holding a holder object gives
/// its records.
fn lines(text: &str, head: bool, problems: &mut Vec<String>) -> Vec<(usize, Json)> {
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match json::parse(line) {
            Ok(document) => {
                records.extend(elements(document).into_iter().map(|(_, r)| (index + 1, r)));
            }
            Err(why) if !head => problems.push(format!("line {}: {why}", index + 1)),
            Err(_) => {}
        }
    }
    records
}

/// A CSV export: each row's `AuditData` JSON.
fn audit_data(text: &str, head: bool, problems: &mut Vec<String>) -> Vec<(usize, Json)> {
    let rows = csv::rows(text);
    let Some((_, header)) = rows.first() else {
        return Vec::new();
    };
    let Some(column) = header.iter().position(|h| h == "AuditData") else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for (line, row) in rows.iter().skip(1) {
        let Some(cell) = row.get(column) else {
            if !head {
                problems.push(format!("line {line}: no AuditData"));
            }
            continue;
        };
        match json::parse(cell) {
            Ok(record) => records.push((*line, record)),
            Err(why) if !head => problems.push(format!("line {line}: AuditData: {why}")),
            Err(_) => {}
        }
    }
    records
}
