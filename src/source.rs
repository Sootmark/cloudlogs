//! Which log a record is from, and where each of its main fields is: a
//! list of candidate paths per field, the first with a value winning, so
//! one table reads the API's, the CLI's and the portal's spellings alike.
//!
//! A path is dotted (`userIdentity.arn`); a number picks an array element
//! (`targetResources.0.displayName`); `Name[Key]` picks, in an array of
//! `{"Name": …, "Value": …}` objects, the value named `Key`.

use common::json::{self, Json};

use crate::{flatten, text, time, Event};

/// A log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// AWS CloudTrail.
    CloudTrail,
    /// Microsoft 365's unified audit log.
    Microsoft365,
    /// Entra ID sign-ins.
    EntraSignIn,
    /// Entra ID directory audits.
    EntraAudit,
    /// Azure's activity log.
    AzureActivity,
    /// Google Cloud logging.
    GoogleCloud,
    /// Google Workspace's audit activities (the Admin SDK Reports API:
    /// admin, login, Drive, OAuth tokens, …), one event each.
    GoogleWorkspace,
}

impl Source {
    /// A short name (`cloudtrail`, `m365`, `entra_signin`, `entra_audit`,
    /// `azure_activity`, `gcp`, `workspace`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CloudTrail => "cloudtrail",
            Self::Microsoft365 => "m365",
            Self::EntraSignIn => "entra_signin",
            Self::EntraAudit => "entra_audit",
            Self::AzureActivity => "azure_activity",
            Self::GoogleCloud => "gcp",
            Self::GoogleWorkspace => "workspace",
        }
    }
}

/// Where a source's main fields are.
struct Mapping {
    time: &'static [&'static str],
    operation: &'static [&'static str],
    service: &'static [&'static str],
    actor: &'static [&'static str],
    actor_id: &'static [&'static str],
    source_ip: &'static [&'static str],
    user_agent: &'static [&'static str],
    target: &'static [&'static str],
    result: &'static [&'static str],
    id: &'static [&'static str],
    location: &'static [&'static str],
}

const CLOUDTRAIL: Mapping = Mapping {
    time: &["eventTime", "EventTime"],
    operation: &["eventName", "EventName"],
    service: &["eventSource", "EventSource"],
    actor: &[
        "Username",
        "userIdentity.userName",
        "userIdentity.sessionContext.sessionIssuer.userName",
        "userIdentity.invokedBy",
        "userIdentity.principalId",
    ],
    actor_id: &["userIdentity.arn"],
    source_ip: &["sourceIPAddress"],
    user_agent: &["userAgent"],
    target: &[
        "requestParameters.bucketName",
        "requestParameters.userName",
        "requestParameters.roleName",
        "requestParameters.policyArn",
        "requestParameters.groupId",
    ],
    result: &["errorCode", "responseElements.ConsoleLogin"],
    id: &["eventID", "EventId"],
    location: &["awsRegion"],
};

const MICROSOFT365: Mapping = Mapping {
    time: &["CreationTime"],
    operation: &["Operation"],
    service: &["Workload"],
    actor: &["UserId"],
    actor_id: &["UserKey"],
    source_ip: &["ClientIP", "ClientIPAddress", "ActorIpAddress"],
    user_agent: &[
        "ExtendedProperties[UserAgent]",
        "ClientInfoString",
        "UserAgent",
    ],
    target: &["ObjectId", "Item.Subject", "DestFolder.Path"],
    result: &["ResultStatus"],
    id: &["Id"],
    location: &[],
};

const ENTRA_SIGNIN: Mapping = Mapping {
    time: &["createdDateTime", "CreatedDateTime", "TimeGenerated"],
    operation: &[],
    service: &["clientAppUsed", "ClientAppUsed"],
    actor: &["userPrincipalName", "UserPrincipalName"],
    actor_id: &["userId", "UserId"],
    source_ip: &["ipAddress", "IPAddress"],
    user_agent: &["userAgent", "UserAgent"],
    target: &[
        "appDisplayName",
        "AppDisplayName",
        "resourceDisplayName",
        "ResourceDisplayName",
    ],
    result: &[],
    id: &["id", "Id"],
    location: &[],
};

const ENTRA_AUDIT: Mapping = Mapping {
    time: &["activityDateTime", "ActivityDateTime", "TimeGenerated"],
    operation: &[
        "activityDisplayName",
        "ActivityDisplayName",
        "OperationName",
    ],
    service: &["loggedByService", "LoggedByService"],
    actor: &[
        "initiatedBy.user.userPrincipalName",
        "initiatedBy.app.displayName",
        "InitiatedBy.user.userPrincipalName",
        "InitiatedBy.app.displayName",
    ],
    actor_id: &[
        "initiatedBy.user.id",
        "initiatedBy.app.servicePrincipalId",
        "InitiatedBy.user.id",
    ],
    source_ip: &["initiatedBy.user.ipAddress", "InitiatedBy.user.ipAddress"],
    user_agent: &[],
    target: &[
        "targetResources.0.userPrincipalName",
        "targetResources.0.displayName",
        "TargetResources.0.userPrincipalName",
        "TargetResources.0.displayName",
    ],
    result: &["result", "Result"],
    id: &["id", "Id"],
    location: &[],
};

const AZURE_ACTIVITY: Mapping = Mapping {
    time: &["eventTimestamp", "event_timestamp", "time", "TimeGenerated"],
    operation: &[
        "operationName.value",
        "operation_name.value",
        "OperationNameValue",
        "operationName",
    ],
    service: &[
        "resourceProviderName.value",
        "resource_provider_name.value",
        "ResourceProviderValue",
    ],
    actor: &["caller", "Caller", "identity.claims.name"],
    actor_id: &[],
    source_ip: &[
        "httpRequest.clientIpAddress",
        "http_request.client_ip_address",
        "callerIpAddress",
        "CallerIpAddress",
    ],
    user_agent: &[],
    target: &["resourceId", "resource_id", "ResourceId", "_ResourceId"],
    result: &[
        "status.value",
        "resultType",
        "ActivityStatusValue",
        "status",
    ],
    id: &[
        "eventDataId",
        "event_data_id",
        "EventDataId",
        "correlationId",
    ],
    location: &[],
};

const GOOGLE_CLOUD: Mapping = Mapping {
    time: &["timestamp", "receiveTimestamp"],
    operation: &[
        "protoPayload.methodName",
        "jsonPayload.event_subtype",
        "jsonPayload.methodName",
    ],
    service: &["protoPayload.serviceName"],
    actor: &[
        "protoPayload.authenticationInfo.principalEmail",
        "jsonPayload.actor.user",
    ],
    actor_id: &["protoPayload.authenticationInfo.principalSubject"],
    source_ip: &["protoPayload.requestMetadata.callerIp"],
    user_agent: &["protoPayload.requestMetadata.callerSuppliedUserAgent"],
    target: &["protoPayload.resourceName"],
    result: &["protoPayload.status.message", "protoPayload.status.code"],
    id: &["insertId"],
    location: &[
        "resource.labels.zone",
        "resource.labels.location",
        "protoPayload.resourceLocation.currentLocations.0",
    ],
};

const GOOGLE_WORKSPACE: Mapping = Mapping {
    time: &["id.time"],
    operation: &["event.name"],
    service: &["id.applicationName"],
    actor: &["actor.email", "actor.key"],
    actor_id: &["actor.profileId"],
    source_ip: &["ipAddress"],
    user_agent: &[],
    target: &[],
    result: &[],
    id: &["id.uniqueQualifier"],
    location: &[],
};

/// The parameters naming what a Workspace event was done to, first found
/// first.
const WORKSPACE_TARGETS: [&str; 8] = [
    "USER_EMAIL",
    "GROUP_EMAIL",
    "target_user",
    "doc_title",
    "app_name",
    "DOMAIN_NAME",
    "SETTING_NAME",
    "affected_email_address",
];

/// Which log a record is from, by the members it has.
pub(crate) fn classify(record: &Json) -> Option<Source> {
    let has = |name: &str| record.get(name).is_some_and(|v| !matches!(v, Json::Null));
    if has("CloudTrailEvent") || (has("eventSource") && has("eventName")) {
        Some(Source::CloudTrail)
    } else if has("CreationTime") && has("Operation") {
        Some(Source::Microsoft365)
    } else if (has("createdDateTime") && (has("userPrincipalName") || has("appDisplayName")))
        || (has("UserPrincipalName") && has("ResultType") && has("AppDisplayName"))
    {
        Some(Source::EntraSignIn)
    } else if (has("activityDateTime") && has("activityDisplayName"))
        || (has("LoggedByService") && has("OperationName") && has("InitiatedBy"))
    {
        Some(Source::EntraAudit)
    } else if (has("operationName") || has("operation_name") || has("OperationNameValue"))
        && (has("resourceId") || has("resource_id") || has("ResourceId") || has("_ResourceId"))
    {
        Some(Source::AzureActivity)
    } else if has("logName") && (has("timestamp") || has("receiveTimestamp")) {
        Some(Source::GoogleCloud)
    } else if record
        .get("id")
        .and_then(|id| id.get("applicationName"))
        .is_some()
        && (has("events") || has("event"))
    {
        Some(Source::GoogleWorkspace)
    } else {
        None
    }
}

/// A record as an event.
pub(crate) fn event(source: Source, record: &Json) -> Event {
    // `lookup-events` wraps each record, as a string, in CloudTrailEvent.
    let inner = record
        .get("CloudTrailEvent")
        .and_then(Json::as_str)
        .and_then(|text| json::parse(text).ok());
    let records: Vec<&Json> = [Some(record), inner.as_ref()]
        .into_iter()
        .flatten()
        .collect();
    let pick = |paths: &[&str]| {
        paths
            .iter()
            .find_map(|path| records.iter().find_map(|r| lookup(r, path)))
    };
    let mapping = match source {
        Source::CloudTrail => &CLOUDTRAIL,
        Source::Microsoft365 => &MICROSOFT365,
        Source::EntraSignIn => &ENTRA_SIGNIN,
        Source::EntraAudit => &ENTRA_AUDIT,
        Source::AzureActivity => &AZURE_ACTIVITY,
        Source::GoogleCloud => &GOOGLE_CLOUD,
        Source::GoogleWorkspace => &GOOGLE_WORKSPACE,
    };
    let mut event = Event {
        source: Some(source),
        time: pick(mapping.time).and_then(|t| time::parse(&t)),
        operation: pick(mapping.operation),
        service: pick(mapping.service),
        actor: pick(mapping.actor),
        actor_id: pick(mapping.actor_id),
        source_ip: pick(mapping.source_ip),
        user_agent: pick(mapping.user_agent),
        target: pick(mapping.target),
        result: pick(mapping.result),
        id: pick(mapping.id),
        location: pick(mapping.location),
        ..Event::default()
    };
    for record in &records {
        flatten(record, "", &mut event.fields);
    }
    // The wrapped record is flattened in its own right.
    event.fields.retain(|(path, _)| path != "CloudTrailEvent");
    match source {
        Source::CloudTrail => cloudtrail(&mut event, &records),
        Source::EntraSignIn => sign_in(&mut event, &records),
        Source::GoogleWorkspace => workspace(&mut event, record),
        _ => {}
    }
    event
}

/// CloudTrail's resources (`resources[].ARN`, or `lookup-events`'
/// `Resources[].ResourceName`) as the target, joined; a call without an
/// error as `Success`.
fn cloudtrail(event: &mut Event, records: &[&Json]) {
    let names: Vec<String> = records
        .iter()
        .flat_map(|record| {
            ["Resources", "resources"]
                .iter()
                .filter_map(|name| record.get(name).and_then(Json::as_array))
                .flatten()
                .filter_map(|r| {
                    ["ResourceName", "ARN"]
                        .iter()
                        .find_map(|key| r.get(key).and_then(text))
                })
                .collect::<Vec<_>>()
        })
        .collect();
    if !names.is_empty() {
        event.target = Some(names.join(", "));
    }
    if event.result.is_none() {
        event.result = Some("Success".to_owned());
    }
}

/// A sign-in: `Sign-in` as the operation, the error code as the result
/// (`0`: `Success`, otherwise the code and the reason), the city and
/// country as the location.
fn sign_in(event: &mut Event, records: &[&Json]) {
    let pick = |paths: &[&str]| {
        paths
            .iter()
            .find_map(|path| records.iter().find_map(|r| lookup(r, path)))
    };
    event.operation = Some("Sign-in".to_owned());
    let code = pick(&["status.errorCode", "ResultType"]);
    let reason = pick(&["status.failureReason", "ResultDescription"]);
    event.result = match (code.as_deref(), reason) {
        (Some("0"), _) => Some("Success".to_owned()),
        (Some(code), Some(reason)) => Some(format!("{code}: {reason}")),
        (Some(code), None) => Some(code.to_owned()),
        (None, reason) => reason,
    };
    let city = pick(&["location.city", "LocationDetails.city"]);
    let country = pick(&[
        "location.countryOrRegion",
        "LocationDetails.countryOrRegion",
        "Location",
    ]);
    event.location = match (city, country) {
        (Some(city), Some(country)) => Some(format!("{city}, {country}")),
        (city, country) => city.or(country),
    };
}

/// A Workspace activity's records: one per event (the API lists them under
/// `events`; Splunk's add-on writes one per line, under `event`), each the
/// activity with that event under `event`.
pub(crate) fn expand(source: Source, record: Json) -> Vec<Json> {
    let Json::Object(members) = record else {
        return vec![record];
    };
    let events = match members.iter().find(|(name, _)| name == "events") {
        Some((_, Json::Array(events))) if source == Source::GoogleWorkspace => events.clone(),
        _ => return vec![Json::Object(members)],
    };
    let activity: Vec<(String, Json)> = members
        .into_iter()
        .filter(|(name, _)| name != "events")
        .collect();
    events
        .into_iter()
        .map(|event| {
            let mut members = activity.clone();
            members.push(("event".to_owned(), event));
            Json::Object(members)
        })
        .collect()
}

/// A Workspace event's parameters as `event.parameters.<name>` (a list's
/// values joined with `, `), and the one naming what it was done to as the
/// target.
fn workspace(event: &mut Event, record: &Json) {
    let parameters = record
        .get("event")
        .and_then(|e| e.get("parameters"))
        .and_then(Json::as_array)
        .unwrap_or_default();
    let mut named = Vec::new();
    for parameter in parameters {
        let Some(name) = parameter.get("name").and_then(Json::as_str) else {
            continue;
        };
        let value = ["value", "boolValue", "intValue"]
            .iter()
            .find_map(|key| parameter.get(key).and_then(text))
            .or_else(|| {
                let values = parameter.get("multiValue")?.as_array()?;
                Some(
                    values
                        .iter()
                        .filter_map(text)
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            });
        if let Some(value) = value {
            named.push((name.to_owned(), value));
        }
    }
    event.target = WORKSPACE_TARGETS.iter().find_map(|wanted| {
        named
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value.clone())
    });
    event
        .fields
        .retain(|(path, _)| !path.starts_with("event.parameters."));
    event.fields.extend(
        named
            .into_iter()
            .map(|(name, value)| (format!("event.parameters.{name}"), value)),
    );
}

/// The value at `path` as text, if not empty.
fn lookup(record: &Json, path: &str) -> Option<String> {
    let mut value = record;
    for segment in path.split('.') {
        value = step(value, segment)?;
    }
    text(value).filter(|t| !t.is_empty())
}

fn step<'a>(value: &'a Json, segment: &str) -> Option<&'a Json> {
    if let Some((array, key)) = segment.strip_suffix(']').and_then(|s| s.split_once('[')) {
        return value.get(array)?.as_array()?.iter().find_map(|item| {
            (item.get("Name").and_then(Json::as_str) == Some(key))
                .then(|| item.get("Value"))
                .flatten()
        });
    }
    match segment.parse::<usize>() {
        Ok(index) => value.as_array()?.get(index),
        Err(_) => value.get(segment),
    }
}
