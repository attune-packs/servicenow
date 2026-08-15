"""Restricted direct HTTP client and dispatcher for ServiceNow REST APIs."""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import re
import tempfile
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote, urlsplit

import requests


DEFAULT_CREDENTIAL_KEY = "servicenow.credentials"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024
MAX_QUERY_LENGTH = 4096
MAX_RECORDS = 10_000
_SYS_ID = re.compile(r"^[0-9a-fA-F]{32}$")
_NAME = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$", re.I)


class ServiceNowPackError(Exception):
    """An action-safe error that never includes response bodies or credentials."""


INCIDENT_READ = {
    "sys_id", "number", "short_description", "description", "state", "priority",
    "impact", "urgency", "category", "subcategory", "assignment_group", "assigned_to",
    "caller_id", "opened_at", "resolved_at", "closed_at", "close_code", "close_notes",
    "sys_created_on", "sys_updated_on",
}
INCIDENT_CREATE = {
    "short_description", "description", "impact", "urgency", "category", "subcategory",
    "assignment_group", "assigned_to", "caller_id", "contact_type", "location",
}
INCIDENT_UPDATE = INCIDENT_CREATE | {"priority", "work_notes", "comments"}
CHANGE_READ = {
    "sys_id", "number", "short_description", "description", "type", "state", "approval",
    "risk", "impact", "priority", "assignment_group", "assigned_to", "requested_by",
    "start_date", "end_date", "work_start", "work_end", "close_code", "close_notes",
    "sys_created_on", "sys_updated_on",
}
CHANGE_CREATE = {
    "short_description", "description", "type", "risk", "impact", "priority",
    "assignment_group", "assigned_to", "requested_by", "start_date", "end_date",
    "implementation_plan", "backout_plan", "test_plan", "justification", "cmdb_ci",
}
CHANGE_UPDATE = CHANGE_CREATE | {"work_notes", "comments"}
CMDB_READ = {
    "sys_id", "name", "sys_class_name", "asset_tag", "serial_number", "operational_status",
    "install_status", "location", "assigned_to", "managed_by", "support_group",
    "short_description", "sys_created_on", "sys_updated_on",
}
CMDB_UPDATE = {
    "name", "asset_tag", "serial_number", "location", "assigned_to", "managed_by",
    "support_group", "short_description", "comments",
}
USER_READ = {"sys_id", "user_name", "name", "email", "active", "department", "manager", "company", "sys_updated_on"}
GROUP_READ = {"sys_id", "name", "description", "active", "manager", "parent", "email", "sys_updated_on"}
ATTACHMENT_READ = {
    "sys_id", "table_name", "table_sys_id", "file_name", "content_type", "size_bytes",
    "size_compressed", "state", "sys_created_by", "sys_created_on", "sys_updated_on",
}
LIFECYCLE_FIELDS = {
    "state", "status", "stage", "phase", "incident_state", "approval", "active",
    "operational_status", "install_status", "close_code", "close_notes", "resolved_at",
    "resolved_by", "closed_at", "closed_by",
}
REFERENCE_FIELDS = {
    "assignment_group", "assigned_to", "caller_id", "location", "requested_by", "cmdb_ci",
    "managed_by", "support_group",
}


def _fetch_key(key_ref: str) -> dict[str, Any]:
    if not isinstance(key_ref, str) or not key_ref.strip():
        raise ServiceNowPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=attune.context.client, key_ref=key_ref)
    except Exception as exc:
        raise ServiceNowPackError(f"could not read ServiceNow credential Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise ServiceNowPackError("ServiceNow credential Key was not found")
        raise ServiceNowPackError(f"could not read ServiceNow credential Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise ServiceNowPackError("ServiceNow credential Key must contain a JSON object") from None
    if not isinstance(value, dict):
        raise ServiceNowPackError("ServiceNow credential Key must contain an object")
    return value


def _nonempty(value: Any, name: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ServiceNowPackError(f"{name} must be a non-empty string no longer than {maximum} characters")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ServiceNowPackError(f"{name} contains a control character")
    return value


def _sys_id(value: Any, name: str = "sys_id") -> str:
    value = _nonempty(value, name, 32)
    if not _SYS_ID.fullmatch(value):
        raise ServiceNowPackError(f"{name} must be a 32-character hexadecimal ServiceNow sys_id")
    return value.lower()


def _api_name(value: Any, name: str) -> str:
    value = _nonempty(value, name, 80)
    if not _NAME.fullmatch(value):
        raise ServiceNowPackError(f"{name} is not a valid ServiceNow API name")
    return value


def _integer(params: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ServiceNowPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise ServiceNowPackError(f"{name} must be a boolean")
    return value


def _field_list(value: Any, name: str = "fields") -> list[str]:
    if not isinstance(value, list) or not value:
        raise ServiceNowPackError(f"{name} must be a non-empty array")
    result: list[str] = []
    for item in value:
        field = _api_name(item, f"{name} item")
        if field not in result:
            result.append(field)
    return result


def _selected_fields(params: dict[str, Any], allowed: set[str]) -> list[str]:
    fields = sorted(allowed) if params.get("fields") is None else _field_list(params["fields"])
    denied = set(fields) - allowed
    if denied:
        raise ServiceNowPackError(f"fields contains disallowed field '{sorted(denied)[0]}'")
    if "sys_id" in allowed and "sys_id" not in fields:
        fields.insert(0, "sys_id")
    return fields


def _body(value: Any, allowed: set[str], name: str = "record") -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise ServiceNowPackError(f"{name} must be a non-empty object")
    result: dict[str, Any] = {}
    for raw_field, item in value.items():
        field = _api_name(raw_field, f"{name} field")
        if field not in allowed:
            raise ServiceNowPackError(f"{name} contains disallowed field '{field}'")
        if isinstance(item, (dict, list)):
            raise ServiceNowPackError(f"{name}.{field} must be a JSON scalar")
        if field in REFERENCE_FIELDS and item not in {None, ""}:
            item = _sys_id(item, f"{name}.{field}")
        result[field] = item
    return result


def _encoded_query(value: Any) -> str:
    value = _nonempty(value, "query", MAX_QUERY_LENGTH)
    if len(value.encode("utf-8")) > MAX_QUERY_LENGTH:
        raise ServiceNowPackError(f"query must not exceed {MAX_QUERY_LENGTH} UTF-8 bytes")
    lowered = value.lower()
    if (
        "javascript:" in lowered
        or "javascript%3a" in lowered
        or re.search(r"(?:^|\^)nq", lowered)
        or re.search(r"%5enq|%(?:0[0-9a-f]|1[0-9a-f]|7f)", lowered)
    ):
        raise ServiceNowPackError("query contains a prohibited encoded-query construct")
    return value


def _query_value(value: Any, name: str) -> str:
    value = _nonempty(value, name, 255)
    if "^" in value or "javascript:" in value.lower():
        raise ServiceNowPackError(f"{name} contains an encoded-query metacharacter")
    return value


def _exact_confirmation(params: dict[str, Any], expected: str) -> None:
    if params.get("confirmation") != expected:
        raise ServiceNowPackError(f"confirmation must exactly equal '{expected}'")


def _response_meta(response: requests.Response) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "etag": response.headers.get("ETag"),
        "last_modified": response.headers.get("Last-Modified"),
        "request_id": response.headers.get("X-Request-ID") or response.headers.get("X-Transaction-ID"),
    }


def _bounded_response_bytes(response: requests.Response, maximum: int, label: str) -> bytes:
    length = response.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > maximum:
        raise ServiceNowPackError(f"{label} exceeded the {maximum // (1024 * 1024)} MiB limit")
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > maximum:
                raise ServiceNowPackError(f"{label} exceeded the {maximum // (1024 * 1024)} MiB limit")
            chunks.append(chunk)
    except requests.RequestException as exc:
        raise ServiceNowPackError(f"ServiceNow response read failed ({type(exc).__name__})") from None
    return b"".join(chunks)


@contextmanager
def _tls_verify(profile: dict[str, Any]) -> Iterator[bool | str]:
    ca_cert = profile.get("ca_cert")
    if ca_cert is None:
        yield True
        return
    if not isinstance(ca_cert, str) or not ca_cert.strip():
        raise ServiceNowPackError("credential ca_cert must be a non-empty PEM string")
    with tempfile.TemporaryDirectory(prefix="attune-servicenow-") as directory:
        path = Path(directory, "ca.pem")
        path.write_text(ca_cert, encoding="utf-8")
        os.chmod(path, 0o600)
        yield str(path)


class ServiceNowClient:
    def __init__(self, profile: dict[str, Any], timeout_seconds: int):
        instance_url = profile.get("instance_url")
        if not isinstance(instance_url, str):
            raise ServiceNowPackError("credential instance_url must be a string")
        parsed = urlsplit(instance_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ServiceNowPackError("credential instance_url must be an HTTPS origin without credentials, path, query, or fragment")
        try:
            parsed.port
        except ValueError:
            raise ServiceNowPackError("credential instance_url has an invalid port") from None
        allowed = profile.get("allowed_hostnames")
        if not isinstance(allowed, list) or not allowed:
            raise ServiceNowPackError("credential allowed_hostnames must be a non-empty array")
        normalized: set[str] = set()
        for value in allowed:
            if not isinstance(value, str) or not _HOSTNAME.fullmatch(value):
                raise ServiceNowPackError("credential allowed_hostnames contains an invalid hostname")
            normalized.add(value.rstrip(".").lower())
        hostname = parsed.hostname.rstrip(".").lower()
        if hostname not in normalized:
            raise ServiceNowPackError("credential instance_url hostname is not explicitly allowed")
        if profile.get("verify_tls", True) is not True:
            raise ServiceNowPackError("credential verify_tls must be true")
        auth = profile.get("auth")
        if not isinstance(auth, dict):
            raise ServiceNowPackError("credential auth must be an object")
        auth_type = auth.get("type")
        if auth_type == "basic":
            username = _nonempty(auth.get("username"), "credential auth.username", 255)
            if ":" in username:
                raise ServiceNowPackError("credential auth.username must not contain ':'")
            _nonempty(auth.get("password"), "credential auth.password", 4096)
        elif auth_type == "oauth":
            access_token = auth.get("access_token")
            if access_token is not None:
                _nonempty(access_token, "credential auth.access_token", 8192)
            else:
                for field in ("client_id", "client_secret", "refresh_token"):
                    _nonempty(auth.get(field), f"credential auth.{field}", 8192)
            token_path = auth.get("token_path", "/oauth_token.do")
            if token_path != "/oauth_token.do":
                raise ServiceNowPackError("credential auth.token_path must be '/oauth_token.do'")
        else:
            raise ServiceNowPackError("credential auth.type must be 'basic' or 'oauth'")
        self.base_url = instance_url.rstrip("/")
        self.profile = profile
        self.auth = auth
        self.timeout = (min(timeout_seconds, 10), timeout_seconds)
        self._access_token: str | None = auth.get("access_token") if auth_type == "oauth" else None

    def _authorization(self) -> str:
        if self.auth["type"] == "basic":
            raw = f"{self.auth['username']}:{self.auth['password']}".encode("utf-8")
            return "Basic " + base64.b64encode(raw).decode("ascii")
        if self._access_token is None:
            try:
                with _tls_verify(self.profile) as verify:
                    response = requests.request(
                        "POST",
                        self.base_url + "/oauth_token.do",
                        data={
                            "grant_type": "refresh_token",
                            "client_id": self.auth["client_id"],
                            "client_secret": self.auth["client_secret"],
                            "refresh_token": self.auth["refresh_token"],
                        },
                        headers={"Accept": "application/json"},
                        timeout=self.timeout,
                        verify=verify,
                        allow_redirects=False,
                        stream=True,
                    )
            except requests.RequestException as exc:
                raise ServiceNowPackError(f"ServiceNow OAuth request failed ({type(exc).__name__})") from None
            if response.status_code != 200:
                response.close()
                raise ServiceNowPackError(f"ServiceNow OAuth returned HTTP {response.status_code}")
            try:
                raw = _bounded_response_bytes(response, MAX_JSON_BYTES, "ServiceNow OAuth response")
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise ServiceNowPackError("ServiceNow OAuth returned invalid JSON") from None
            finally:
                response.close()
            token = payload.get("access_token") if isinstance(payload, dict) else None
            self._access_token = _nonempty(token, "ServiceNow OAuth access token", 8192)
        return "Bearer " + self._access_token

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: Any = None,
        data: Any = None,
        content_type: str | None = None,
        headers: dict[str, str] | None = None,
        expected: set[int] | None = None,
        stream: bool = False,
    ) -> tuple[Any, dict[str, Any], requests.Response]:
        request_headers = {"Accept": "application/json", "Authorization": self._authorization()}
        if body is not None:
            request_headers["Content-Type"] = "application/json"
        if content_type is not None:
            request_headers["Content-Type"] = content_type
        request_headers.update(headers or {})
        try:
            with _tls_verify(self.profile) as verify:
                response = requests.request(
                    method,
                    self.base_url + path,
                    params=query or {},
                    json=body,
                    data=data,
                    headers=request_headers,
                    timeout=self.timeout,
                    verify=verify,
                    allow_redirects=False,
                    stream=True,
                )
        except requests.RequestException as exc:
            raise ServiceNowPackError(f"ServiceNow request failed ({type(exc).__name__})") from None
        statuses = expected or {200, 201, 204}
        if response.status_code not in statuses:
            response.close()
            if response.status_code in {409, 412}:
                raise ServiceNowPackError(f"ServiceNow rejected a stale record version (HTTP {response.status_code})")
            raise ServiceNowPackError(f"ServiceNow returned HTTP {response.status_code}")
        meta = _response_meta(response)
        if stream:
            return None, meta, response
        try:
            raw = _bounded_response_bytes(response, MAX_JSON_BYTES, "ServiceNow response")
        finally:
            response.close()
        if not raw:
            return {"success": True}, meta, response
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ServiceNowPackError("ServiceNow returned invalid JSON") from None
        if not isinstance(payload, dict) or "result" not in payload:
            raise ServiceNowPackError("ServiceNow returned an unexpected response contract")
        return payload["result"], meta, response


def _profile_policy(profile: dict[str, Any], table: str) -> dict[str, Any]:
    allowlist = profile.get("table_allowlist")
    if not isinstance(allowlist, dict) or table not in allowlist or not isinstance(allowlist[table], dict):
        raise ServiceNowPackError("table is not present in the credential table_allowlist")
    raw = allowlist[table]
    allowed_keys = {"read_fields", "write_fields", "allow_create", "allow_update", "allow_delete", "allow_attachments"}
    if set(raw) - allowed_keys:
        raise ServiceNowPackError("credential table_allowlist policy contains an unsupported setting")
    read_fields = set(_field_list(raw.get("read_fields"), "credential read_fields"))
    write_fields = set(_field_list(raw.get("write_fields"), "credential write_fields")) if raw.get("write_fields") is not None else set()
    if LIFECYCLE_FIELDS & write_fields:
        raise ServiceNowPackError("credential generic write_fields cannot include lifecycle fields")
    if not {"sys_id", "sys_updated_on"} <= read_fields:
        raise ServiceNowPackError("credential read_fields must include sys_id and sys_updated_on")
    booleans: dict[str, bool] = {}
    for key in ("allow_create", "allow_update", "allow_delete", "allow_attachments"):
        value = raw.get(key, False)
        if not isinstance(value, bool):
            raise ServiceNowPackError(f"credential {key} must be a boolean")
        booleans[key] = value
    return {"read": read_fields, "write": write_fields, **booleans}


def _static_policy(table: str) -> dict[str, Any]:
    policies = {
        "incident": {"read": INCIDENT_READ, "create": INCIDENT_CREATE, "update": INCIDENT_UPDATE},
        "change_request": {"read": CHANGE_READ, "create": CHANGE_CREATE, "update": CHANGE_UPDATE},
        "cmdb_ci": {"read": CMDB_READ, "create": set(), "update": CMDB_UPDATE},
        "sys_user": {"read": USER_READ, "create": set(), "update": set()},
        "sys_user_group": {"read": GROUP_READ, "create": set(), "update": set()},
    }
    return policies[table]


def _record_path(table: str, sys_id: str | None = None) -> str:
    path = f"/api/now/table/{quote(table, safe='')}"
    return path if sys_id is None else path + "/" + sys_id


def _list_records(
    client: ServiceNowClient,
    table: str,
    allowed_fields: set[str],
    params: dict[str, Any],
    *,
    fixed_query: str | None = None,
    api_path: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    fields = _selected_fields(params, allowed_fields)
    query_value = fixed_query
    if query_value is None and params.get("query") is not None:
        query_value = _encoded_query(params["query"])
    page_size = _integer(params, "limit", 100, 1, 1000)
    offset = _integer(params, "offset", 0, 0, 1_000_000)
    paginate = _boolean(params, "paginate")
    max_records = _integer(params, "max_records", page_size, 1, MAX_RECORDS) if paginate else page_size
    records: list[dict[str, Any]] = []
    pages = 0
    cursor = offset
    last_meta: dict[str, Any] = {}
    full_page = False
    while len(records) < max_records:
        requested = min(page_size, max_records - len(records))
        query: dict[str, Any] = {
            "sysparm_fields": ",".join(fields),
            "sysparm_limit": requested,
            "sysparm_offset": cursor,
            "sysparm_display_value": "false",
            "sysparm_exclude_reference_link": "true",
        }
        if query_value is not None:
            query["sysparm_query"] = query_value
        result, last_meta, _ = client.request("GET", api_path or _record_path(table), query=query, expected={200})
        if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
            raise ServiceNowPackError("ServiceNow returned an invalid record list")
        records.extend(result)
        pages += 1
        cursor += len(result)
        full_page = len(result) == requested
        if not paginate or not full_page:
            break
    meta = {
        **last_meta,
        "table": table,
        "count": len(records),
        "offset": offset,
        "pages": pages,
        "has_more": full_page,
        "next_offset": cursor if full_page else None,
        "fields": fields,
    }
    return records, meta


def _get_record(
    client: ServiceNowClient,
    table: str,
    sys_id: str,
    fields: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    selected = list(dict.fromkeys(["sys_id", *fields]))
    result, meta, _ = client.request(
        "GET",
        _record_path(table, sys_id),
        query={"sysparm_fields": ",".join(selected), "sysparm_display_value": "false", "sysparm_exclude_reference_link": "true"},
        expected={200},
    )
    if not isinstance(result, dict) or str(result.get("sys_id", "")).lower() != sys_id:
        raise ServiceNowPackError("ServiceNow returned a different or invalid record")
    return result, {**meta, "table": table, "sys_id": sys_id, "fields": fields}


def _conflict_headers(
    client: ServiceNowClient,
    table: str,
    sys_id: str,
    params: dict[str, Any],
    *,
    always_read: bool = False,
) -> tuple[dict[str, str], dict[str, Any] | None]:
    expected_updated = params.get("expected_sys_updated_on")
    if expected_updated is not None:
        expected_updated = _nonempty(expected_updated, "expected_sys_updated_on", 64)
    supplied_etag = params.get("if_match")
    if supplied_etag is not None:
        supplied_etag = _nonempty(supplied_etag, "if_match", 256)
    current: dict[str, Any] | None = None
    meta: dict[str, Any] = {}
    if always_read or expected_updated is not None:
        current, meta = _get_record(client, table, sys_id, ["sys_updated_on"])
        if expected_updated is not None and current.get("sys_updated_on") != expected_updated:
            raise ServiceNowPackError("record sys_updated_on no longer matches expected_sys_updated_on")
    etag = supplied_etag or (meta.get("etag") if expected_updated is not None else None)
    return ({"If-Match": etag} if etag else {}), current


def _create_record(client: ServiceNowClient, table: str, record: dict[str, Any], fields: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    result, meta, _ = client.request(
        "POST",
        _record_path(table),
        query={"sysparm_fields": ",".join(list(dict.fromkeys(["sys_id", *fields]))), "sysparm_display_value": "false", "sysparm_exclude_reference_link": "true"},
        body=record,
        expected={201},
    )
    if not isinstance(result, dict) or not _SYS_ID.fullmatch(str(result.get("sys_id", ""))):
        raise ServiceNowPackError("ServiceNow create returned an invalid record")
    return result, {**meta, "table": table, "sys_id": result["sys_id"], "fields": fields}


def _update_record(
    client: ServiceNowClient,
    table: str,
    sys_id: str,
    record: dict[str, Any],
    fields: list[str],
    params: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    headers, _ = _conflict_headers(client, table, sys_id, params)
    result, meta, _ = client.request(
        "PATCH",
        _record_path(table, sys_id),
        query={"sysparm_fields": ",".join(list(dict.fromkeys(["sys_id", *fields]))), "sysparm_display_value": "false", "sysparm_exclude_reference_link": "true"},
        body=record,
        headers=headers,
        expected={200},
    )
    if not isinstance(result, dict) or str(result.get("sys_id", "")).lower() != sys_id:
        raise ServiceNowPackError("ServiceNow updated a different or invalid record")
    return result, {**meta, "table": table, "sys_id": sys_id, "fields": fields}


def _delete_record(client: ServiceNowClient, table: str, sys_id: str, params: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    _exact_confirmation(params, f"DELETE {table}:{sys_id}")
    headers, current = _conflict_headers(client, table, sys_id, params, always_read=True)
    _, meta, _ = client.request("DELETE", _record_path(table, sys_id), headers=headers, expected={204})
    return {"deleted": True, "table": table, "sys_id": sys_id, "previous_sys_updated_on": current.get("sys_updated_on") if current else None}, {**meta, "table": table, "sys_id": sys_id}


def _state_value(profile: dict[str, Any], family: str, transition: str) -> str:
    mappings = profile.get("state_mappings")
    family_map = mappings.get(family) if isinstance(mappings, dict) else None
    value = family_map.get(transition) if isinstance(family_map, dict) else None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    return _nonempty(value, f"credential state_mappings.{family}.{transition}", 80)


def _artifact_path(relative: Any, *, must_exist: bool) -> Path:
    root_value = os.environ.get("ATTUNE_ARTIFACTS_DIR")
    if not root_value:
        raise ServiceNowPackError("ATTUNE_ARTIFACTS_DIR is not set")
    root = Path(root_value).resolve(strict=True)
    if not root.is_dir():
        raise ServiceNowPackError("ATTUNE_ARTIFACTS_DIR is not a directory")
    relative = _nonempty(relative, "artifact_path", 1024)
    if any(segment in {"", ".", ".."} for segment in relative.split("/")):
        raise ServiceNowPackError("artifact_path must use non-empty segments other than '.' or '..'")
    candidate_input = Path(relative)
    if candidate_input.is_absolute():
        raise ServiceNowPackError("artifact_path must be a confined relative path")
    if must_exist:
        try:
            candidate = (root / candidate_input).resolve(strict=True)
        except OSError:
            raise ServiceNowPackError("artifact_path does not exist") from None
        if not candidate.is_file():
            raise ServiceNowPackError("artifact_path must identify a regular file")
    else:
        try:
            parent = (root / candidate_input.parent).resolve(strict=True)
        except OSError:
            raise ServiceNowPackError("artifact_path parent directory does not exist") from None
        candidate = parent / candidate_input.name
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ServiceNowPackError("artifact_path escapes ATTUNE_ARTIFACTS_DIR") from None
    return candidate


def _attachment_tables(client: ServiceNowClient) -> set[str]:
    raw_tables = client.profile.get("attachment_table_allowlist")
    if not isinstance(raw_tables, list) or not raw_tables:
        raise ServiceNowPackError("credential attachment_table_allowlist must be a non-empty array")
    tables: set[str] = set()
    for raw_table in raw_tables:
        table = _api_name(raw_table, "credential attachment_table_allowlist item")
        if table not in {"incident", "change_request"}:
            policy = _profile_policy(client.profile, table)
            if not policy["allow_attachments"]:
                raise ServiceNowPackError("custom attachment table policy must set allow_attachments true")
        tables.add(table)
    return tables


def _attachment_metadata(client: ServiceNowClient, sys_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    result, meta, _ = client.request("GET", f"/api/now/attachment/{sys_id}", expected={200})
    if not isinstance(result, dict) or str(result.get("sys_id", "")).lower() != sys_id:
        raise ServiceNowPackError("ServiceNow returned a different or invalid attachment")
    table = result.get("table_name")
    if table not in _attachment_tables(client):
        raise ServiceNowPackError("attachment table is not allowed by this credential profile")
    return {field: result.get(field) for field in sorted(ATTACHMENT_READ) if field in result}, {**meta, "sys_id": sys_id, "table": table}


def _execute(client: ServiceNowClient, operation: str, params: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    if operation.startswith("table_"):
        table = _api_name(params.get("table"), "table")
        policy = _profile_policy(client.profile, table)
        if operation == "table_list":
            return _list_records(client, table, policy["read"], params)
        sys_id = _sys_id(params.get("sys_id")) if operation != "table_create" else None
        if operation == "table_get":
            fields = _selected_fields(params, policy["read"])
            return _get_record(client, table, sys_id, fields)
        if operation == "table_create":
            if not policy["allow_create"]:
                raise ServiceNowPackError("table create is not allowed by the credential profile")
            record = _body(params.get("record"), policy["write"])
            return _create_record(client, table, record, sorted(policy["read"]))
        if operation == "table_update":
            if not policy["allow_update"]:
                raise ServiceNowPackError("table update is not allowed by the credential profile")
            record = _body(params.get("record"), policy["write"])
            return _update_record(client, table, sys_id, record, sorted(policy["read"]), params)
        if operation == "table_delete":
            if not policy["allow_delete"]:
                raise ServiceNowPackError("table delete is not allowed by the credential profile")
            return _delete_record(client, table, sys_id, params)

    if operation.startswith("incident_"):
        policy = _static_policy("incident")
        if operation == "incident_list":
            return _list_records(client, "incident", policy["read"], params)
        if operation == "incident_create":
            record = _body(params.get("record"), policy["create"])
            if not record.get("short_description"):
                raise ServiceNowPackError("record.short_description is required")
            return _create_record(client, "incident", record, sorted(policy["read"]))
        sys_id = _sys_id(params.get("sys_id"))
        if operation == "incident_get":
            return _get_record(client, "incident", sys_id, _selected_fields(params, policy["read"]))
        if operation == "incident_update":
            record = _body(params.get("record"), policy["update"])
            return _update_record(client, "incident", sys_id, record, sorted(policy["read"]), params)
        if operation in {"incident_resolve", "incident_close"}:
            transition = "resolved" if operation == "incident_resolve" else "closed"
            state = _state_value(client.profile, "incident", transition)
            _exact_confirmation(params, f"TRANSITION incident:{sys_id} TO {transition}:{state}")
            close_notes = _nonempty(params.get("close_notes"), "close_notes", 4000)
            record: dict[str, Any] = {"state": state, "close_notes": close_notes}
            if operation == "incident_resolve":
                record["close_code"] = _nonempty(params.get("close_code"), "close_code", 80)
            return _update_record(client, "incident", sys_id, record, sorted(policy["read"]), params)

    if operation.startswith("change_"):
        policy = _static_policy("change_request")
        if operation == "change_list":
            return _list_records(client, "change_request", policy["read"], params)
        if operation == "change_create":
            record = _body(params.get("record"), policy["create"])
            if not record.get("short_description"):
                raise ServiceNowPackError("record.short_description is required")
            return _create_record(client, "change_request", record, sorted(policy["read"]))
        sys_id = _sys_id(params.get("sys_id"))
        if operation == "change_get":
            return _get_record(client, "change_request", sys_id, _selected_fields(params, policy["read"]))
        if operation == "change_update":
            record = _body(params.get("record"), policy["update"])
            return _update_record(client, "change_request", sys_id, record, sorted(policy["read"]), params)
        if operation == "change_transition":
            transition = _api_name(params.get("transition"), "transition")
            state = _state_value(client.profile, "change_request", transition)
            _exact_confirmation(params, f"TRANSITION change_request:{sys_id} TO {transition}:{state}")
            return _update_record(client, "change_request", sys_id, {"state": state}, sorted(policy["read"]), params)

    if operation == "cmdb_ci_lookup":
        if params.get("sys_id") is not None and params.get("name") is not None:
            raise ServiceNowPackError("sys_id and name are mutually exclusive")
        if params.get("sys_id") is not None:
            return _get_record(client, "cmdb_ci", _sys_id(params["sys_id"]), _selected_fields(params, CMDB_READ))
        name = _query_value(params.get("name"), "name")
        _integer(params, "limit", 20, 1, 100)
        return _list_records(client, "cmdb_ci", CMDB_READ, params, fixed_query=f"name={name}")

    if operation == "cmdb_ci_update":
        sys_id = _sys_id(params.get("sys_id"))
        return _update_record(client, "cmdb_ci", sys_id, _body(params.get("record"), CMDB_UPDATE), sorted(CMDB_READ), params)

    if operation in {"user_lookup", "group_lookup"}:
        is_user = operation == "user_lookup"
        table = "sys_user" if is_user else "sys_user_group"
        allowed = USER_READ if is_user else GROUP_READ
        lookup_name = "user_name" if is_user else "name"
        if params.get("sys_id") is not None and params.get(lookup_name) is not None:
            raise ServiceNowPackError(f"sys_id and {lookup_name} are mutually exclusive")
        if params.get("sys_id") is not None:
            return _get_record(client, table, _sys_id(params["sys_id"]), _selected_fields(params, allowed))
        identifier = params.get(lookup_name)
        field = lookup_name
        value = _query_value(identifier, field)
        _integer(params, "limit", 20, 1, 100)
        return _list_records(client, table, allowed, params, fixed_query=f"{field}={value}")

    if operation == "attachment_list":
        table = _api_name(params.get("table"), "table")
        if table not in _attachment_tables(client):
            raise ServiceNowPackError("attachment table is not allowed by this credential profile")
        record_id = _sys_id(params.get("record_sys_id"), "record_sys_id")
        # Verify the attachment target and avoid listing metadata for a stale/wrong record ID.
        read_fields = _static_policy(table)["read"] if table in {"incident", "change_request"} else _profile_policy(client.profile, table)["read"]
        _get_record(client, table, record_id, ["sys_updated_on"] if "sys_updated_on" in read_fields else ["sys_id"])
        fixed = f"table_name={table}^table_sys_id={record_id}"
        return _list_records(client, "sys_attachment", ATTACHMENT_READ, params, fixed_query=fixed, api_path="/api/now/attachment")

    if operation == "attachment_upload":
        table = _api_name(params.get("table"), "table")
        if table not in _attachment_tables(client):
            raise ServiceNowPackError("attachment table is not allowed by this credential profile")
        record_id = _sys_id(params.get("record_sys_id"), "record_sys_id")
        read_fields = _static_policy(table)["read"] if table in {"incident", "change_request"} else _profile_policy(client.profile, table)["read"]
        _get_record(client, table, record_id, ["sys_updated_on"] if "sys_updated_on" in read_fields else ["sys_id"])
        path = _artifact_path(params.get("artifact_path"), must_exist=True)
        maximum = _integer(params, "max_bytes", MAX_ATTACHMENT_BYTES, 1, 1024 * 1024 * 1024)
        size = path.stat().st_size
        if size > maximum:
            raise ServiceNowPackError("attachment exceeds max_bytes")
        remote_name = params.get("file_name") or path.name
        remote_name = _nonempty(remote_name, "file_name", 255)
        if "/" in remote_name or "\\" in remote_name:
            raise ServiceNowPackError("file_name must not contain path separators")
        content_type = params.get("content_type") or mimetypes.guess_type(remote_name)[0] or "application/octet-stream"
        content_type = _nonempty(content_type, "content_type", 255)
        with path.open("rb") as source:
            result, meta, _ = client.request(
                "POST",
                "/api/now/attachment/file",
                query={"table_name": table, "table_sys_id": record_id, "file_name": remote_name},
                data=source,
                content_type=content_type,
                expected={201},
            )
        if not isinstance(result, dict) or not _SYS_ID.fullmatch(str(result.get("sys_id", ""))):
            raise ServiceNowPackError("ServiceNow upload returned invalid attachment metadata")
        return {field: result.get(field) for field in sorted(ATTACHMENT_READ) if field in result}, {**meta, "table": table, "record_sys_id": record_id, "bytes_uploaded": size}

    if operation == "attachment_download":
        attachment_id = _sys_id(params.get("sys_id"))
        attachment, attachment_meta = _attachment_metadata(client, attachment_id)
        path = _artifact_path(params.get("artifact_path"), must_exist=False)
        overwrite = _boolean(params, "overwrite")
        if path.exists() and not overwrite:
            raise ServiceNowPackError("artifact_path already exists; set overwrite to replace it")
        maximum = _integer(params, "max_bytes", MAX_ATTACHMENT_BYTES, 1, 1024 * 1024 * 1024)
        _, meta, response = client.request(
            "GET",
            f"/api/now/attachment/{attachment_id}/file",
            headers={"Accept": "application/octet-stream"},
            expected={200},
            stream=True,
        )
        length = response.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > maximum:
            response.close()
            raise ServiceNowPackError("attachment exceeds max_bytes")
        written = 0
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".servicenow-", dir=path.parent, delete=False) as target:
                temp_name = target.name
                try:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if not chunk:
                            continue
                        written += len(chunk)
                        if written > maximum:
                            raise ServiceNowPackError("attachment exceeds max_bytes")
                        target.write(chunk)
                except requests.RequestException as exc:
                    raise ServiceNowPackError(f"ServiceNow attachment read failed ({type(exc).__name__})") from None
                target.flush()
                os.fsync(target.fileno())
            os.chmod(temp_name, 0o600)
            if overwrite:
                os.replace(temp_name, path)
            else:
                try:
                    os.link(temp_name, path)
                except FileExistsError:
                    raise ServiceNowPackError("artifact_path was created during download") from None
                os.unlink(temp_name)
            temp_name = None
        finally:
            response.close()
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
        return {"attachment": attachment, "artifact_path": params["artifact_path"], "bytes_downloaded": written}, {**attachment_meta, **meta}

    if operation == "attachment_delete":
        attachment_id = _sys_id(params.get("sys_id"))
        attachment, attachment_meta = _attachment_metadata(client, attachment_id)
        _exact_confirmation(params, f"DELETE sys_attachment:{attachment_id}")
        headers = {"If-Match": attachment_meta["etag"]} if attachment_meta.get("etag") else None
        _, meta, _ = client.request("DELETE", f"/api/now/attachment/{attachment_id}", headers=headers, expected={204})
        return {"deleted": True, "attachment": attachment}, {**attachment_meta, **meta}

    raise ServiceNowPackError("unsupported ServiceNow action")


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    timeout = _integer(params, "timeout_seconds", 30, 1, 120)
    credential = _fetch_key(params.get("credential_key", DEFAULT_CREDENTIAL_KEY))
    client = ServiceNowClient(credential, timeout)
    data, meta = _execute(client, operation, params)
    return {"operation": operation, "data": data, "meta": meta}
