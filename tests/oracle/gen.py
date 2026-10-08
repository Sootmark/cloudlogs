"""Writes written.tsv: the main fields of the records in
tests/fixtures/written/, read with Python's own JSON and CSV modules and
picked by the providers' documented field names, one line per record: the
file, its position, the log, the time (UTC, ISO 8601), the operation,
service, actor, actor id, source address, user agent, target, result, id
and location. Independent of this crate: no code shared.

Run: python3 -I tests/oracle/gen.py tests/fixtures/written > tests/oracle/written.tsv
     python3 -I tests/oracle/gen.py tests/fixtures/attack_data > tests/oracle/attack_data.tsv
"""

import csv
import datetime
import io
import json
import pathlib
import sys


def get(record, path):
    value = record
    for step in path.split("."):
        if isinstance(value, list):
            value = value[int(step)] if step.isdigit() and int(step) < len(value) else None
        elif isinstance(value, dict):
            value = value.get(step)
        else:
            return None
    if value is None or isinstance(value, (dict, list)):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value) or None


def first(record, *paths):
    return next((v for v in (get(record, p) for p in paths) if v), None)


def named(record, array, name):
    for item in record.get(array) or []:
        if item.get("Name") == name:
            return item.get("Value")
    return None


def iso(text):
    moment = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    moment = moment.astimezone(datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}0Z"


def cloudtrail(r):
    targets = [x.get("ARN") for x in r.get("resources") or [] if x.get("ARN")]
    return ("cloudtrail", r["eventTime"], r["eventName"], r["eventSource"],
            first(r, "userIdentity.userName", "userIdentity.sessionContext.sessionIssuer.userName"),
            get(r, "userIdentity.arn"), get(r, "sourceIPAddress"), get(r, "userAgent"),
            ", ".join(targets) or first(r, "requestParameters.bucketName", "requestParameters.userName"),
            first(r, "errorCode", "responseElements.ConsoleLogin") or "Success",
            get(r, "eventID"), get(r, "awsRegion"))


def m365(r):
    return ("m365", r["CreationTime"], r["Operation"], r["Workload"], get(r, "UserId"), get(r, "UserKey"),
            first(r, "ClientIP", "ClientIPAddress"),
            named(r, "ExtendedProperties", "UserAgent") or get(r, "ClientInfoString"),
            get(r, "ObjectId"), get(r, "ResultStatus"), get(r, "Id"), None)


def sign_in(r):
    code = first(r, "status.errorCode", "ResultType")
    reason = first(r, "status.failureReason", "ResultDescription")
    result = "Success" if code == "0" else (f"{code}: {reason}" if reason else code)
    city = first(r, "location.city", "LocationDetails.city")
    country = first(r, "location.countryOrRegion", "LocationDetails.countryOrRegion", "Location")
    return ("entra_signin", first(r, "createdDateTime", "TimeGenerated"), "Sign-in",
            first(r, "clientAppUsed", "ClientAppUsed"), first(r, "userPrincipalName", "UserPrincipalName"),
            first(r, "userId", "UserId"), first(r, "ipAddress", "IPAddress"), first(r, "userAgent", "UserAgent"),
            first(r, "appDisplayName", "AppDisplayName"), result, first(r, "id", "Id"),
            f"{city}, {country}" if city and country else (city or country))


def audit(r):
    return ("entra_audit", r["activityDateTime"], r["activityDisplayName"], r["loggedByService"],
            first(r, "initiatedBy.user.userPrincipalName", "initiatedBy.app.displayName"),
            get(r, "initiatedBy.user.id"), get(r, "initiatedBy.user.ipAddress"), None,
            first(r, "targetResources.0.userPrincipalName", "targetResources.0.displayName"),
            get(r, "result"), get(r, "id"), None)


def azure(r):
    return ("azure_activity", r["time"], r["operationName"], None, get(r, "identity.claims.name"), None,
            get(r, "callerIpAddress"), None, get(r, "resourceId"), get(r, "resultType"),
            get(r, "correlationId"), None)


TARGETS = ["USER_EMAIL", "GROUP_EMAIL", "target_user", "doc_title", "app_name", "DOMAIN_NAME",
           "SETTING_NAME", "affected_email_address"]


def parameter(p):
    for key in ("value", "boolValue", "intValue"):
        if key in p:
            v = p[key]
            return ("true" if v else "false") if isinstance(v, bool) else str(v)
    if "multiValue" in p:
        return ", ".join(str(v) for v in p["multiValue"])
    return None


def workspace(r):
    params = {}
    for p in r["event"].get("parameters") or []:
        value = parameter(p)
        if value is not None:
            params.setdefault(p["name"], value)
    target = next((params[t] for t in TARGETS if t in params), None)
    return ("workspace", r["id"]["time"], r["event"]["name"], r["id"]["applicationName"],
            get(r, "actor.email"), get(r, "actor.profileId"), get(r, "ipAddress"), None,
            target, None, get(r, "id.uniqueQualifier"), None)


def classify(r):
    if "applicationName" in (r.get("id") or {}):
        return workspace(r)
    if "eventSource" in r:
        return cloudtrail(r)
    if "CreationTime" in r:
        return m365(r)
    if "createdDateTime" in r or "ResultType" in r:
        return sign_in(r)
    if "activityDateTime" in r:
        return audit(r)
    return azure(r)


def records(path):
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix == ".csv":
        return [(i, json.loads(row["AuditData"])) for i, row in enumerate(csv.DictReader(io.StringIO(text)), 2)]
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return [(i, json.loads(line)) for i, line in enumerate(text.splitlines(), 1) if line.strip()]
    for holder in ("Records", "records", "value", "items"):
        if isinstance(document, dict) and holder in document:
            document = document[holder]
    if isinstance(document, dict):
        document = [document]
    return list(enumerate(document, 1))


def events(record):
    """A Workspace activity's events, one record each."""
    if "events" not in record:
        return [record]
    activity = {k: v for k, v in record.items() if k != "events"}
    return [dict(activity, event=e) for e in record["events"]]


def main(folder):
    lines = []
    for path in sorted(pathlib.Path(folder).glob("*")):
        if path.name in ("NOTICE", "LICENSE"):
            continue
        for position, activity in records(path):
            for record in events(activity):
                fields = list(classify(record))
                fields[1] = iso(fields[1])
                lines.append("\t".join([path.name, str(position)] + [f or "" for f in fields]))
    print("\n".join(lines))


main(sys.argv[1])
