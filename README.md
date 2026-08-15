# ServiceNow Attune Pack

This Attune pack adapts the Apache-2.0 StackStorm Exchange ServiceNow pack at
revision `15bc510dc05143562497b9974805ed1fba189885`. It replaces the stale
`pysnow==0.6.5` integration with one restricted direct HTTP client over the
current ServiceNow Table, Attachment, and OAuth APIs. See [SOURCE.md](SOURCE.md)
for exact provenance and reviewed API references.

## Requirements

- Python 3.10 or newer on the selected Attune worker.
- Network reachability from the worker to the explicitly allowed ServiceNow instance.
- An encrypted pack-owned Attune Key, normally `servicenow.credentials`.
- ServiceNow ACLs and roles scoped to the exact tables, records, and fields needed.
- `ATTUNE_ARTIFACTS_DIR` on the worker for attachment upload and download.

The pack does not elevate ServiceNow privileges. Instance ACLs, business rules,
data policies, mandatory fields, domain separation, plugins, and customizations
remain authoritative.

## Credential Profiles

All actions take only a Key reference. Passwords, OAuth material, host policy,
state mappings, and generic API allowlists stay in the protected Key.

Basic authentication profile:

```json
{
  "instance_url": "https://example.service-now.com",
  "allowed_hostnames": ["example.service-now.com"],
  "verify_tls": true,
  "auth": {
    "type": "basic",
    "username": "attune.integration",
    "password": "REDACTED"
  },
  "table_allowlist": {
    "u_automation_task": {
      "read_fields": ["sys_id", "number", "short_description", "status", "sys_updated_on"],
      "write_fields": ["short_description"],
      "allow_create": true,
      "allow_update": true,
      "allow_delete": false,
      "allow_attachments": true
    }
  },
  "attachment_table_allowlist": ["incident", "change_request", "u_automation_task"],
  "state_mappings": {
    "incident": {"resolved": "6", "closed": "7"},
    "change_request": {"assess": "-4", "authorize": "-3", "implement": "-1", "closed": "3"}
  }
}
```

OAuth refresh-token profile:

```json
{
  "instance_url": "https://example.service-now.com",
  "allowed_hostnames": ["example.service-now.com"],
  "verify_tls": true,
  "ca_cert": "-----BEGIN CERTIFICATE-----\nREDACTED_CA_PEM\n-----END CERTIFICATE-----",
  "auth": {
    "type": "oauth",
    "client_id": "REDACTED_CLIENT_ID",
    "client_secret": "REDACTED_CLIENT_SECRET",
    "refresh_token": "REDACTED_REFRESH_TOKEN"
  },
  "table_allowlist": {},
  "attachment_table_allowlist": ["incident", "change_request"],
  "state_mappings": {
    "incident": {"resolved": "6", "closed": "7"},
    "change_request": {"implement": "-1", "review": "0", "closed": "3"}
  }
}
```

OAuth profiles may instead contain a non-empty `access_token`; it remains
in-memory for one action execution. Refresh uses only the same instance's
`/oauth_token.do` endpoint. Tokens are not written to disk or returned.

`instance_url` must be an HTTPS origin without credentials or a path, and its
exact hostname must appear in `allowed_hostnames`. Wildcards are rejected.
Redirects are disabled. TLS verification is mandatory; `ca_cert`, when set, is
written to a mode-0600 temporary file and removed after each request.

## Actions

| Action | Purpose |
|---|---|
| `servicenow.table_list` | List selected fields from one profile-allowlisted table |
| `servicenow.table_get` | Get one allowlisted record by `sys_id` |
| `servicenow.table_create` | Create with allowlisted scalar write fields |
| `servicenow.table_update` | Patch one `sys_id` with allowlisted non-lifecycle fields |
| `servicenow.table_delete` | Delete one `sys_id` after policy, preflight, and confirmation |
| `servicenow.incident_list` | Query incidents with bounded pagination |
| `servicenow.incident_get` | Get one incident by `sys_id` |
| `servicenow.incident_create` | Create an incident using curated fields |
| `servicenow.incident_update` | Update curated non-lifecycle fields |
| `servicenow.incident_resolve` | Apply mapped resolved state and closure information |
| `servicenow.incident_close` | Apply mapped closed state and close notes |
| `servicenow.change_list` | Query change requests with bounded pagination |
| `servicenow.change_get` | Get one change request by `sys_id` |
| `servicenow.change_create` | Create a change request using curated fields |
| `servicenow.change_update` | Update curated non-lifecycle fields |
| `servicenow.change_transition` | Apply a named, profile-mapped state |
| `servicenow.attachment_list` | List metadata for attachments on one verified record |
| `servicenow.attachment_upload` | Upload a confined artifact to one verified record |
| `servicenow.attachment_download` | Atomically write attachment bytes under the artifact root |
| `servicenow.attachment_delete` | Delete verified attachment metadata and bytes |
| `servicenow.cmdb_ci_lookup` | Read a base CI by preferred `sys_id` or exact name |
| `servicenow.cmdb_ci_update` | Update conservative common base-CI fields by `sys_id` |
| `servicenow.user_lookup` | Read a user by preferred `sys_id` or exact `user_name` |
| `servicenow.group_lookup` | Read a group by preferred `sys_id` or exact name |

## Generic Table Policy

Generic operations cannot access a table absent from `table_allowlist` and
cannot read or write a field absent from that table's field lists. Create,
update, delete, and attachment access have separate booleans. Policies are
validated before any request.

Every generic `read_fields` list must include `sys_id` and `sys_updated_on` for
identity and conflict checks. Generic `write_fields` cannot contain common
lifecycle fields such as `state`, `status`, `stage`, `approval`, `active`,
CMDB status fields, close fields, or resolved/closed audit fields. This prevents generic
updates from bypassing reviewed lifecycle actions and confirmations. Generic
bodies must be flat JSON objects with scalar values. Record updates and deletes
accept only a 32-character hexadecimal `sys_id`; they never mutate by display
name, number, or encoded query. Curated reference fields such as assignee,
group, caller, location, requested-by, CI, manager, and support group likewise
accept only `sys_id` values (or null/empty values when clearing is permitted).

## Queries And Pagination

List actions send encoded queries as URL query parameters, not by string URL
concatenation. Queries are limited to 4096 characters and UTF-8 bytes and reject
controls, encoded controls, `javascript:`, and `^NQ`. Lookup actions construct one exact condition and
reject the `^` metacharacter in values. Encoded queries are available only on
read/list actions.

`limit` maps to `sysparm_limit` and `offset` maps to `sysparm_offset`.
`paginate: true` follows offsets until a short page or `max_records`; the latter
is capped at 10,000. Selected fields map to `sysparm_fields`. Responses request
raw values, always retain `sys_id`, and omit reference links so contracts remain predictable. `meta`
contains count, page count, current/next offset, fields, status, and available
ETag/request metadata.

## Conflicts And Mutations

Update and transition actions accept `expected_sys_updated_on`. When supplied,
the client preflights that exact `sys_id`, compares the value, and propagates a
returned ETag in `If-Match`. Callers may instead supply `if_match` directly.
ServiceNow instances do not expose ETags uniformly, and the
`sys_updated_on` preflight is not an atomic compare-and-swap when no ETag is
available. HTTP 409 and 412 are reported as stale-version conflicts.

The client performs no request retries. A create, patch, delete, transition, or
attachment upload is sent at most once. OAuth refresh, target verification, and
conflict preflight are separate non-mutating requests.

Destructive and lifecycle actions require these exact confirmations, using the
canonical lowercase `sys_id` and the raw state value stored in the profile:

```text
DELETE <table>:<sys_id>
DELETE sys_attachment:<sys_id>
TRANSITION incident:<sys_id> TO resolved:<mapped_state>
TRANSITION incident:<sys_id> TO closed:<mapped_state>
TRANSITION change_request:<sys_id> TO <transition>:<mapped_state>
```

ServiceNow state models can differ by workflow, plugin, table extension, and
customer configuration. No incident or change state number is hard-coded.
Every lifecycle action resolves its raw state from protected `state_mappings`.
Business rules may still reject a transition or require additional fields.

## Attachments

Every attachment target table must appear in `attachment_table_allowlist`.
Custom tables must also be in `table_allowlist` with `allow_attachments: true`.
The client preflights target records and verifies attachment metadata before
download or deletion.

Upload and download paths must be relative to the resolved
`ATTUNE_ARTIFACTS_DIR`. Absolute paths, missing parents, empty/`.`/`..` segments,
and resolved escapes are rejected. Uploads require an existing regular file.
Downloads use a private temporary file in the destination directory, enforce
`max_bytes` while streaming, flush to disk, chmod to 0600, and atomically
replace the destination only when allowed. The default bound is 100 MiB.

## Outputs And Errors

All actions receive one flat JSON object on stdin and return:

```json
{
  "operation": "incident_get",
  "data": {"sys_id": "0123456789abcdef0123456789abcdef", "number": "INC0010001"},
  "meta": {
    "status_code": 200,
    "etag": null,
    "last_modified": null,
    "request_id": null,
    "table": "incident",
    "sys_id": "0123456789abcdef0123456789abcdef",
    "fields": ["number", "sys_id"]
  }
}
```

Errors include only a local category, exception class, or HTTP status. Remote
response bodies, request headers, URLs, passwords, and OAuth values are not
included. Unknown entry-point exceptions are reduced to their class name.

## Deferred APIs

Import Set and Service Catalog requests are current but intentionally omitted
from this generic pack. Transform maps, staging result contracts, catalog item
variables, user criteria, requested-for rules, and flows are deployment-specific
and need a separately reviewed action contract. No arbitrary endpoint runner is
provided.

## Validation

```bash
python3 -m unittest discover -s tests -v
attune --output json pack check /home/david/Codebase/attune-packs/servicenow
attune pack test /home/david/Codebase/attune-packs/servicenow --detailed
```

Tests mock every ServiceNow and Attune Key call. A live tenant remains required
to verify ACLs, OAuth registration, custom CA trust, state mappings, dictionary
fields, business rules, domain separation, attachment limits, and installed
plugins.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and modification details are in [NOTICE](NOTICE).
