# cloudlogs

Cloud and SaaS audit logs, for forensics: who did what, from where, to which resource, and whether it worked, as AWS, Microsoft and Google export them. One dependency, its sibling `sootmark-common` (JSON, times).

```toml
[dependencies]
sootmark-cloudlogs = "0.3"
```

```rust
let log = cloudlogs::read(&std::fs::read("AuditLog_2024-03-05.csv")?);
for event in &log.events {
    println!("{:?} {:?} {:?} from {:?}", event.time, event.actor, event.operation, event.source_ip);
}
```

## What you get

- **AWS CloudTrail**: the S3 log files (`{"Records": […]}`), and `aws cloudtrail lookup-events` output (the record in `CloudTrailEvent` read with the wrapper's user name and resources).
- **Microsoft 365 unified audit log**: records as JSON or JSON lines, and the CSV the Purview portal and `Search-UnifiedAuditLog` export (each record's JSON in `AuditData`), the user agent found in `ExtendedProperties` or `ClientInfoString`.
- **Entra ID**: sign-ins and directory audits as Microsoft Graph and the portal give them, and Log Analytics' `SigninLogs` and `AuditLogs`; a sign-in's result is `Success` or its error code and reason, its location the city and country.
- **Azure activity log**: the REST API's and diagnostic settings' JSON, the Azure CLI's and SDK's snake case, and Log Analytics' `AzureActivity`.
- **Google Cloud logging**: audit logs (`protoPayload`) and other entries (`jsonPayload`, `textPayload`), as `gcloud logging read` writes them.
- **Google Workspace**: the audit activities the Admin SDK Reports API lists (admin console, logins, Drive, OAuth tokens, …), and the lines Splunk's add-on writes: one event per activity event, its name as the operation, the application as the service, the parameter naming what it was done to (user, group, document, app) as the target, and every parameter by name (`event.parameters.<name>`, a list's values joined).
- Whatever the container (a JSON array, an object holding the records under `Records`, `records`, `value`, `Events` or `items`, JSON lines, the CSV), each record gives an `Event`: time (UTC), operation, service, actor and actor id, source address, user agent, target, result, id, location; and every value, flattened to dotted paths, in `fields`. Records of other logs are counted in `problems`; nothing panics.

## How it's checked

- plaso's samples (Apache-2.0, `tests/fixtures/plaso/`): every one of the 25 records plaso reads from its CloudTrail, Microsoft 365, Azure activity and Google Cloud samples, read the same (`tests/oracle/plaso.tsv`).
- The formats plaso has no samples of (a CloudTrail S3 file, a Purview CSV export, Entra ID sign-ins and audits from Graph and Log Analytics, an Azure diagnostic record), written for these tests after the documented formats (`tests/fixtures/written/`): every record's main fields as Python's own JSON and CSV modules read them (`tests/oracle/written.tsv`).
- Google Workspace: Splunk's attack_data samples (Apache-2.0, `tests/fixtures/attack_data/`: admin and login activities, 42 events) and activities written as the Reports API lists them, read the same way (`tests/oracle/attack_data.tsv`, `written.tsv`).
- Property tests: arbitrary text, records cut anywhere and deep nesting give events, problems or nothing, never a panic.

## Licence

MIT or Apache-2.0, at your option.
