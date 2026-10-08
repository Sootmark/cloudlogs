//! Cloud and SaaS audit logs, for forensics: who did what, from where,
//! to which resource, and whether it worked, as the providers export
//! them.
//!
//! - AWS CloudTrail: the S3 log files (`{"Records": […]}`), and what
//!   `aws cloudtrail lookup-events` prints (each event's record in
//!   `CloudTrailEvent`).
//! - Microsoft 365's unified audit log: records as JSON, and the CSV the
//!   Purview portal and `Search-UnifiedAuditLog` export (each record's JSON
//!   in `AuditData`).
//! - Entra ID sign-ins and directory audits: Microsoft Graph's JSON (the
//!   portal's download), and Log Analytics' `SigninLogs` and `AuditLogs`.
//! - Azure's activity log: the REST API's and diagnostic settings' JSON,
//!   and the Azure CLI's and SDK's spelling.
//! - Google Cloud's audit and other logs (`gcloud logging read`'s JSON).
//! - Google Workspace's audit activities, as the Admin SDK Reports API
//!   lists them (admin, login, Drive, OAuth tokens, …) and as Splunk's
//!   add-on writes them: one event per activity event, its parameters by
//!   name.
//!
//! Whatever the container (a JSON array, an object holding the records
//! under `Records`, `records`, `value`, `Events` or `items`, JSON lines, or that
//! CSV), each record becomes an [`Event`] with the same main fields, and
//! all its values, flattened, in `fields`.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let log = cloudlogs::read(&std::fs::read("AuditLog_2024-03-05.csv")?);
//! for event in &log.events {
//!     println!("{:?} {:?} {:?} from {:?}", event.time, event.actor, event.operation, event.source_ip);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Records that can't be read go to `problems`, never a panic.

mod container;
mod csv;
mod source;
mod time;

use common::json::Json;
use common::time::Ts;

pub use source::Source;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The most values kept from one record's flattening.
const MAX_FIELDS: usize = 512;

/// One record.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Event {
    /// Which log it is from.
    pub source: Option<Source>,
    /// Its position in the file, from 1 (a line for JSON lines and CSV, an
    /// element otherwise).
    pub position: usize,
    /// Its place among the events of one record, from 0: a Google
    /// Workspace activity holds several.
    pub part: usize,
    /// When it happened (UTC).
    pub time: Option<Ts>,
    /// What was done (`ConsoleLogin`, `MailItemsAccessed`, `Sign-in`,
    /// `Microsoft.Compute/virtualMachines/write`,
    /// `google.iam.admin.v1.CreateServiceAccount`).
    pub operation: Option<String>,
    /// The service it was done in (`iam.amazonaws.com`, `Exchange`,
    /// `Office 365 Exchange Online`, `compute.googleapis.com`).
    pub service: Option<String>,
    /// Who did it: a user name, an e-mail address, a role session.
    pub actor: Option<String>,
    /// The actor's identifier: an ARN, an object id, a key.
    pub actor_id: Option<String>,
    /// From where.
    pub source_ip: Option<String>,
    /// With what client.
    pub user_agent: Option<String>,
    /// To what: a resource, an object, an application.
    pub target: Option<String>,
    /// How it went: `Success`, an error code, a status.
    pub result: Option<String>,
    /// The record's identifier.
    pub id: Option<String>,
    /// Where (an AWS region, a sign-in's city and country).
    pub location: Option<String>,
    /// Every value of the record, dotted paths (`userIdentity.arn`,
    /// `Parameters.0.Value`), up to 512.
    pub fields: Vec<(String, String)>,
}

impl Event {
    /// A value by its dotted path.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, v)| v.as_str())
    }
}

/// A file's events and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Log {
    /// The events, in order.
    pub events: Vec<Event>,
    /// What couldn't be read, with why.
    pub problems: Vec<String>,
}

/// Whether `head` starts like a cloud audit log, and which.
#[must_use]
pub fn detect(head: &[u8]) -> Option<Source> {
    let mut problems = Vec::new();
    container::records(head, true, &mut problems)
        .into_iter()
        .find_map(|(_, record)| source::classify(&record))
}

/// Read a file.
#[must_use]
pub fn read(data: &[u8]) -> Log {
    let mut log = Log::default();
    let records = container::records(data, false, &mut log.problems);
    let mut unknown = 0usize;
    for (position, record) in records {
        let Some(source) = source::classify(&record) else {
            unknown += 1;
            continue;
        };
        for (part, record) in source::expand(source, record).into_iter().enumerate() {
            let mut event = source::event(source, &record);
            event.position = position;
            event.part = part;
            log.events.push(event);
        }
    }
    if unknown > 0 {
        log.problems
            .push(format!("{unknown} records of no log this crate reads"));
    }
    log
}

/// Every leaf of `json` as a dotted path and its text.
fn flatten(json: &Json, prefix: &str, into: &mut Vec<(String, String)>) {
    if into.len() >= MAX_FIELDS {
        return;
    }
    let join = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}.{name}")
        }
    };
    match json {
        Json::Object(members) => {
            for (name, value) in members {
                flatten(value, &join(name), into);
            }
        }
        Json::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                flatten(item, &join(&index.to_string()), into);
            }
        }
        Json::Null => {}
        leaf => {
            if let Some(text) = text(leaf).filter(|t| !t.is_empty()) {
                into.push((prefix.to_owned(), text));
            }
        }
    }
}

/// A scalar as text: strings as they are, numbers and booleans as JSON
/// writes them.
fn text(json: &Json) -> Option<String> {
    match json {
        Json::String(s) => Some(s.clone()),
        Json::Bool(b) => Some(b.to_string()),
        Json::Int(n) => Some(n.to_string()),
        Json::UInt(n) => Some(n.to_string()),
        Json::Float(n) => Some(n.to_string()),
        _ => None,
    }
}
