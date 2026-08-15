from __future__ import annotations

import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

try:
    import requests
except ModuleNotFoundError:
    # Attune's local test runner does not install pack requirements.
    requests = types.ModuleType("requests")

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    requests.RequestException = RequestException
    requests.ConnectionError = ConnectionError
    requests.Response = object
    requests.request = mock.Mock(side_effect=ConnectionError("network unavailable"))
    requests.exceptions = types.SimpleNamespace(JSONDecodeError=ValueError)
    sys.modules["requests"] = requests


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import servicenow_client as client  # noqa: E402


SYS_ID = "0123456789abcdef0123456789abcdef"
OTHER_ID = "fedcba9876543210fedcba9876543210"


class Response:
    def __init__(self, result=None, status_code=200, headers=None, content=None, chunks=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._result = result
        self.content = json.dumps({"result": result}).encode() if content is None else content
        self._chunks = chunks if chunks is not None else [self.content]
        self.closed = False

    def json(self):
        if isinstance(self._result, Exception):
            raise self._result
        return {"result": self._result}

    def iter_content(self, chunk_size=1):
        yield from self._chunks

    def close(self):
        self.closed = True


def profile(**overrides):
    value = {
        "instance_url": "https://dev12345.service-now.com",
        "allowed_hostnames": ["dev12345.service-now.com"],
        "verify_tls": True,
        "auth": {"type": "basic", "username": "automation", "password": "TOP-SECRET"},
        "table_allowlist": {
            "u_task": {
                "read_fields": ["sys_id", "name", "status", "sys_updated_on"],
                "write_fields": ["name"],
                "allow_create": True,
                "allow_update": True,
                "allow_delete": True,
                "allow_attachments": True,
            }
        },
        "attachment_table_allowlist": ["incident", "change_request", "u_task"],
        "state_mappings": {
            "incident": {"resolved": "6", "closed": "7"},
            "change_request": {"assess": "-4", "implement": "-1", "closed": "3"},
        },
    }
    value.update(overrides)
    return value


def snow(**overrides):
    return client.ServiceNowClient(profile(**overrides), 30)


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {path.stem: path.read_text(encoding="utf-8") for path in sorted((ROOT / "actions").glob("*.yaml"))}

    def test_curated_action_inventory(self):
        self.assertEqual(
            {
                "attachment_delete", "attachment_download", "attachment_list", "attachment_upload",
                "change_create", "change_get", "change_list", "change_transition", "change_update",
                "cmdb_ci_lookup", "cmdb_ci_update", "group_lookup",
                "incident_close", "incident_create", "incident_get", "incident_list", "incident_resolve", "incident_update",
                "table_create", "table_delete", "table_get", "table_list", "table_update", "user_lookup",
            },
            set(self.actions),
        )

    def test_actions_use_flat_stdin_json_contracts_and_key_refs(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                expected = {
                    "ref": f"servicenow.{name}", "runner_type": "python", "runtime_version": '\">=3.10\"',
                    "entry_point": "servicenow_action.py", "parameter_delivery": "stdin",
                    "parameter_format": "json", "output_format": "json",
                }
                for field, value in expected.items():
                    self.assertRegex(text, rf"(?m)^{field}: {re.escape(value)}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(text, r"credential_key: \{[^\n]*default: servicenow\.credentials[^\n]*\}")
                for field in ("operation", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {field}: \{{type:")
                self.assertNotRegex(text, r"(?m)^  (password|access_token|refresh_token):")

    def test_source_license_and_no_pysnow(self):
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        revision = "15bc510dc05143562497b9974805ed1fba189885"
        self.assertIn(f'source_revision: "{revision}"', pack)
        self.assertIn('source_version: "1.0.0-4-g15bc510"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn(revision, (ROOT / "NOTICE").read_text(encoding="utf-8"))
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertNotIn("pysnow", (ROOT / "requirements.txt").read_text(encoding="utf-8").lower())


class ProfileTests(unittest.TestCase):
    def test_instance_requires_https_exact_hostname_allowlist_and_no_url_credentials(self):
        invalid = [
            {"instance_url": "http://dev12345.service-now.com"},
            {"instance_url": "https://user:secret@dev12345.service-now.com"},
            {"instance_url": "https://dev12345.service-now.com/api/now"},
            {"instance_url": "https://evil.example", "allowed_hostnames": ["dev12345.service-now.com"]},
            {"allowed_hostnames": ["*.service-now.com"]},
            {"verify_tls": False},
        ]
        for overrides in invalid:
            with self.subTest(overrides=overrides), self.assertRaises(client.ServiceNowPackError):
                snow(**overrides)

    def test_auth_profiles_are_strict(self):
        invalid = [
            {"auth": {"type": "basic", "username": "user", "password": "secret\nheader"}},
            {"auth": {"type": "basic", "username": "user:other", "password": "secret"}},
            {"auth": {"type": "oauth", "client_id": "id", "client_secret": "secret"}},
            {"auth": {"type": "oauth", "access_token": "token", "token_path": "https://evil.invalid/token"}},
            {"auth": {"type": "bearer", "access_token": "token"}},
        ]
        for overrides in invalid:
            with self.subTest(overrides=overrides), self.assertRaises(client.ServiceNowPackError):
                snow(**overrides)

    def test_generic_policy_rejects_lifecycle_fields_and_unknown_settings(self):
        for policy in (
            {"read_fields": ["sys_id"], "write_fields": ["state"]},
            {"read_fields": ["sys_id", "sys_updated_on"], "write_fields": ["status"]},
            {"read_fields": ["sys_id", "sys_updated_on"], "write_fields": ["install_status"]},
            {"read_fields": ["sys_id"], "unknown": True},
        ):
            with self.subTest(policy=policy), self.assertRaises(client.ServiceNowPackError):
                client._profile_policy(profile(table_allowlist={"incident": policy}), "incident")

    def test_custom_ca_file_is_private_and_removed(self):
        with client._tls_verify({"ca_cert": "CA PEM"}) as verify:
            path = Path(verify)
            self.assertEqual("CA PEM", path.read_text(encoding="utf-8"))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertFalse(path.exists())


class TableApiTests(unittest.TestCase):
    @mock.patch("requests.request")
    def test_list_uses_field_allowlist_encoded_params_and_offset_pagination(self, request):
        request.side_effect = [
            Response([{"sys_id": SYS_ID, "name": "one"}, {"sys_id": OTHER_ID, "name": "two"}]),
            Response([{"sys_id": "a" * 32, "name": "three"}]),
        ]
        data, meta = client._execute(snow(), "table_list", {
            "table": "u_task", "fields": ["sys_id", "name"], "query": "status=ready^ORDERBYname",
            "limit": 2, "offset": 4, "paginate": True, "max_records": 5,
        })
        self.assertEqual(3, len(data))
        self.assertEqual(2, meta["pages"])
        self.assertFalse(meta["has_more"])
        self.assertEqual(2, request.call_count)
        first = request.call_args_list[0]
        self.assertEqual("https://dev12345.service-now.com/api/now/table/u_task", first.args[1])
        self.assertEqual("status=ready^ORDERBYname", first.kwargs["params"]["sysparm_query"])
        self.assertEqual(4, first.kwargs["params"]["sysparm_offset"])
        self.assertEqual(6, request.call_args_list[1].kwargs["params"]["sysparm_offset"])

    def test_queries_reject_controls_javascript_and_nq(self):
        for query in (
            "active=true\nadmin=true", "active=true\u0085admin=true", "sys_id=javascript:gs.getUserID()",
            "sys_id=javascript%3Ags.getUserID()", "active=true^NQpriority=1", "active=true%5ENQpriority=1",
            "name=" + "\u20ac" * 2000,
        ):
            with self.subTest(query=query), self.assertRaises(client.ServiceNowPackError):
                client._execute(snow(), "table_list", {"table": "u_task", "query": query})

    def test_arbitrary_table_and_field_access_is_denied(self):
        with self.assertRaisesRegex(client.ServiceNowPackError, "table_allowlist"):
            client._execute(snow(), "table_list", {"table": "sys_user_has_role"})
        with self.assertRaisesRegex(client.ServiceNowPackError, "disallowed field"):
            client._execute(snow(), "table_list", {"table": "u_task", "fields": ["password"]})
        with self.assertRaisesRegex(client.ServiceNowPackError, "JSON scalar"):
            client._execute(snow(), "table_create", {"table": "u_task", "record": {"name": {"nested": True}}})
        with self.assertRaisesRegex(client.ServiceNowPackError, "32-character"):
            client._execute(snow(), "incident_update", {"sys_id": SYS_ID, "record": {"assigned_to": "alice"}})

    @mock.patch("requests.request")
    def test_record_lists_always_retain_sys_id(self, request):
        request.return_value = Response([{"sys_id": SYS_ID, "name": "one"}])
        _, meta = client._execute(snow(), "table_list", {"table": "u_task", "fields": ["name"]})
        self.assertEqual(["sys_id", "name"], meta["fields"])
        self.assertEqual("sys_id,name", request.call_args.kwargs["params"]["sysparm_fields"])

    @mock.patch("requests.request")
    def test_update_is_one_patch_and_validates_returned_sys_id(self, request):
        request.return_value = Response({"sys_id": SYS_ID, "name": "new", "sys_updated_on": "2026-08-15 01:02:03"})
        data, _ = client._execute(snow(), "table_update", {"table": "u_task", "sys_id": SYS_ID, "record": {"name": "new"}})
        self.assertEqual(SYS_ID, data["sys_id"])
        self.assertEqual(1, request.call_count)
        self.assertEqual("PATCH", request.call_args.args[0])
        request.return_value = Response({"sys_id": OTHER_ID})
        with self.assertRaisesRegex(client.ServiceNowPackError, "different"):
            client._execute(snow(), "table_update", {"table": "u_task", "sys_id": SYS_ID, "record": {"name": "new"}})

    @mock.patch("requests.request")
    def test_conflict_preflight_and_etag_propagation(self, request):
        request.side_effect = [
            Response({"sys_id": SYS_ID, "sys_updated_on": "2026-08-15 01:02:03"}, headers={"ETag": '"version-7"'}),
            Response({"sys_id": SYS_ID, "name": "new"}),
        ]
        client._execute(snow(), "table_update", {
            "table": "u_task", "sys_id": SYS_ID, "record": {"name": "new"},
            "expected_sys_updated_on": "2026-08-15 01:02:03",
        })
        self.assertEqual('"version-7"', request.call_args_list[1].kwargs["headers"]["If-Match"])
        request.reset_mock()
        request.side_effect = [Response({"sys_id": SYS_ID, "sys_updated_on": "later"})]
        with self.assertRaisesRegex(client.ServiceNowPackError, "no longer matches"):
            client._execute(snow(), "table_update", {
                "table": "u_task", "sys_id": SYS_ID, "record": {"name": "new"},
                "expected_sys_updated_on": "earlier",
            })
        self.assertEqual(1, request.call_count)

    @mock.patch("requests.request")
    def test_delete_requires_exact_confirmation_and_preflights_record(self, request):
        with self.assertRaisesRegex(client.ServiceNowPackError, "exactly equal"):
            client._execute(snow(), "table_delete", {"table": "u_task", "sys_id": SYS_ID, "confirmation": "yes"})
        request.assert_not_called()
        request.side_effect = [
            Response({"sys_id": SYS_ID, "sys_updated_on": "now"}, headers={"ETag": '"8"'}),
            Response(status_code=204, content=b""),
        ]
        data, _ = client._execute(snow(), "table_delete", {
            "table": "u_task", "sys_id": SYS_ID, "confirmation": f"DELETE u_task:{SYS_ID}",
        })
        self.assertTrue(data["deleted"])
        self.assertEqual(["GET", "DELETE"], [call.args[0] for call in request.call_args_list])


class ItsmTests(unittest.TestCase):
    @mock.patch("requests.request")
    def test_incident_create_uses_curated_fields(self, request):
        request.return_value = Response({"sys_id": SYS_ID, "number": "INC0010001", "short_description": "Disk full"}, status_code=201)
        data, _ = client._execute(snow(), "incident_create", {"record": {"short_description": "Disk full", "impact": "2"}})
        self.assertEqual("INC0010001", data["number"])
        self.assertEqual({"short_description": "Disk full", "impact": "2"}, request.call_args.kwargs["json"])
        with self.assertRaisesRegex(client.ServiceNowPackError, "short_description"):
            client._execute(snow(), "incident_create", {"record": {"description": "missing summary"}})
        with self.assertRaisesRegex(client.ServiceNowPackError, "disallowed field"):
            client._execute(snow(), "incident_update", {"sys_id": SYS_ID, "record": {"state": "7"}})

    @mock.patch("requests.request")
    def test_incident_transition_uses_profile_mapping_and_exact_confirmation(self, request):
        request.return_value = Response({"sys_id": SYS_ID, "state": "6", "close_code": "Solved (Permanently)"})
        params = {
            "sys_id": SYS_ID, "close_code": "Solved (Permanently)", "close_notes": "Replaced disk",
            "confirmation": f"TRANSITION incident:{SYS_ID} TO resolved:6",
        }
        client._execute(snow(), "incident_resolve", params)
        self.assertEqual({"state": "6", "close_notes": "Replaced disk", "close_code": "Solved (Permanently)"}, request.call_args.kwargs["json"])
        with self.assertRaisesRegex(client.ServiceNowPackError, "exactly equal"):
            client._execute(snow(), "incident_close", {"sys_id": SYS_ID, "close_notes": "done", "confirmation": "CLOSE"})

    @mock.patch("requests.request")
    def test_change_transition_does_not_assume_global_state_model(self, request):
        request.return_value = Response({"sys_id": SYS_ID, "state": "-4"})
        client._execute(snow(), "change_transition", {
            "sys_id": SYS_ID, "transition": "assess",
            "confirmation": f"TRANSITION change_request:{SYS_ID} TO assess:-4",
        })
        self.assertEqual({"state": "-4"}, request.call_args.kwargs["json"])
        with self.assertRaisesRegex(client.ServiceNowPackError, "state_mappings"):
            client._execute(snow(), "change_transition", {
                "sys_id": SYS_ID, "transition": "authorize", "confirmation": "unused",
            })

    def test_lookup_values_cannot_inject_encoded_queries(self):
        for operation, params in (
            ("user_lookup", {"user_name": "alice^ORactive=true"}),
            ("group_lookup", {"name": "ops^NQactive=true"}),
            ("cmdb_ci_lookup", {"name": "server^ORDERBYname"}),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(client.ServiceNowPackError, "metacharacter"):
                client._execute(snow(), operation, params)


class AttachmentTests(unittest.TestCase):
    def test_artifact_path_is_confined(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}):
            Path(directory, "ok.txt").write_text("ok", encoding="utf-8")
            self.assertEqual(Path(directory, "ok.txt"), client._artifact_path("ok.txt", must_exist=True))
            for path in ("../outside", "/tmp/absolute", "nested/../outside", "./out", "nested//out"):
                with self.subTest(path=path), self.assertRaises(client.ServiceNowPackError):
                    client._artifact_path(path, must_exist=False)

    def test_attachment_tables_are_explicit_and_custom_tables_need_both_guards(self):
        with self.assertRaisesRegex(client.ServiceNowPackError, "attachment_table_allowlist"):
            client._attachment_tables(snow(attachment_table_allowlist=None))
        bad_policy = profile()["table_allowlist"]
        bad_policy["u_task"] = {**bad_policy["u_task"], "allow_attachments": False}
        with self.assertRaisesRegex(client.ServiceNowPackError, "allow_attachments"):
            client._attachment_tables(snow(table_allowlist=bad_policy))

    @mock.patch("requests.request")
    def test_list_uses_attachment_api_after_target_preflight(self, request):
        request.side_effect = [
            Response({"sys_id": SYS_ID, "sys_updated_on": "now"}),
            Response([{"sys_id": OTHER_ID, "table_name": "incident", "table_sys_id": SYS_ID, "file_name": "log.txt"}]),
        ]
        data, _ = client._execute(snow(), "attachment_list", {"table": "incident", "record_sys_id": SYS_ID})
        self.assertEqual("log.txt", data[0]["file_name"])
        self.assertEqual("https://dev12345.service-now.com/api/now/attachment", request.call_args_list[1].args[1])
        self.assertEqual(f"table_name=incident^table_sys_id={SYS_ID}", request.call_args_list[1].kwargs["params"]["sysparm_query"])

    @mock.patch("requests.request")
    def test_upload_reads_only_confined_file_and_verifies_target(self, request):
        request.side_effect = [
            Response({"sys_id": SYS_ID, "sys_updated_on": "now"}),
            Response({"sys_id": OTHER_ID, "table_name": "incident", "table_sys_id": SYS_ID, "file_name": "evidence.txt"}, status_code=201),
        ]
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}):
            Path(directory, "evidence.txt").write_bytes(b"evidence")
            data, meta = client._execute(snow(), "attachment_upload", {
                "table": "incident", "record_sys_id": SYS_ID, "artifact_path": "evidence.txt",
            })
        self.assertEqual(OTHER_ID, data["sys_id"])
        self.assertEqual(8, meta["bytes_uploaded"])
        upload = request.call_args_list[1]
        self.assertEqual("/api/now/attachment/file", upload.args[1].replace("https://dev12345.service-now.com", ""))
        self.assertNotIn("TOP-SECRET", repr(upload.kwargs["params"]))

    @mock.patch("requests.request")
    def test_download_is_bounded_atomic_and_confined(self, request):
        metadata = {"sys_id": OTHER_ID, "table_name": "incident", "table_sys_id": SYS_ID, "file_name": "evidence.bin"}
        streamed = Response(content=b"", chunks=[b"abc", b"def"], headers={"Content-Length": "6"})
        request.side_effect = [Response(metadata), streamed]
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"ATTUNE_ARTIFACTS_DIR": directory}):
            data, _ = client._execute(snow(), "attachment_download", {"sys_id": OTHER_ID, "artifact_path": "out.bin", "max_bytes": 6})
            self.assertEqual(b"abcdef", Path(directory, "out.bin").read_bytes())
            self.assertEqual(0o600, Path(directory, "out.bin").stat().st_mode & 0o777)
        self.assertEqual(6, data["bytes_downloaded"])
        self.assertTrue(streamed.closed)

    @mock.patch("requests.request")
    def test_delete_verifies_metadata_and_confirmation(self, request):
        metadata = {"sys_id": OTHER_ID, "table_name": "incident", "table_sys_id": SYS_ID, "file_name": "evidence.bin"}
        request.return_value = Response(metadata)
        with self.assertRaisesRegex(client.ServiceNowPackError, "exactly equal"):
            client._execute(snow(), "attachment_delete", {"sys_id": OTHER_ID, "confirmation": "yes"})
        self.assertEqual(1, request.call_count)
        request.reset_mock()
        request.side_effect = [Response(metadata), Response(status_code=204, content=b"")]
        data, _ = client._execute(snow(), "attachment_delete", {
            "sys_id": OTHER_ID, "confirmation": f"DELETE sys_attachment:{OTHER_ID}",
        })
        self.assertTrue(data["deleted"])
        self.assertEqual(["GET", "DELETE"], [call.args[0] for call in request.call_args_list])


class AuthenticationAndErrorsTests(unittest.TestCase):
    @mock.patch("requests.request")
    def test_oauth_refresh_is_same_origin_cached_and_not_returned(self, request):
        token_response = Response(content=json.dumps({"access_token": "OAUTH-TOP-SECRET"}).encode())
        token_response.json = mock.Mock(return_value={"access_token": "OAUTH-TOP-SECRET"})
        request.side_effect = [token_response, Response([]), Response([])]
        auth = {"type": "oauth", "client_id": "client", "client_secret": "secret", "refresh_token": "refresh"}
        oauth_client = snow(auth=auth)
        client._execute(oauth_client, "incident_list", {})
        client._execute(oauth_client, "incident_list", {})
        self.assertEqual("https://dev12345.service-now.com/oauth_token.do", request.call_args_list[0].args[1])
        self.assertEqual("Bearer OAUTH-TOP-SECRET", request.call_args_list[1].kwargs["headers"]["Authorization"])
        self.assertEqual(3, request.call_count)

    @mock.patch("requests.request")
    def test_http_and_transport_errors_are_redacted_and_not_retried(self, request):
        request.return_value = Response({"error": "TOP-SECRET"}, status_code=403)
        with self.assertRaises(client.ServiceNowPackError) as caught:
            client._execute(snow(), "incident_list", {})
        self.assertNotIn("TOP-SECRET", str(caught.exception))
        self.assertEqual(1, request.call_count)
        request.reset_mock()
        request.side_effect = requests.ConnectionError("TOP-SECRET in transport")
        with self.assertRaises(client.ServiceNowPackError) as caught:
            client._execute(snow(), "incident_list", {})
        self.assertNotIn("TOP-SECRET", str(caught.exception))
        self.assertEqual(1, request.call_count)

    @mock.patch("requests.request")
    def test_json_response_is_streamed_with_a_hard_size_bound(self, request):
        oversized = Response([], headers={"Content-Length": str(client.MAX_JSON_BYTES + 1)})
        request.return_value = oversized
        with self.assertRaisesRegex(client.ServiceNowPackError, "16 MiB"):
            client._execute(snow(), "incident_list", {})
        self.assertTrue(request.call_args.kwargs["stream"])
        self.assertTrue(oversized.closed)

    @mock.patch("requests.request")
    def test_stream_read_exceptions_are_redacted(self, request):
        response = Response([])
        response.iter_content = mock.Mock(side_effect=requests.ConnectionError("TOP-SECRET stream detail"))
        request.return_value = response
        with self.assertRaises(client.ServiceNowPackError) as caught:
            client._execute(snow(), "incident_list", {})
        self.assertNotIn("TOP-SECRET", str(caught.exception))
        self.assertTrue(response.closed)


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util

        spec = importlib.util.spec_from_file_location("servicenow_action_test", ROOT / "actions" / "servicenow_action.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_invalid_input_and_unknown_errors_do_not_echo_secrets(self):
        for raw, error in (("[]", None), ('{"password":"DO-NOT-ECHO"}', RuntimeError("DO-NOT-ECHO"))):
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = mock.patch.object(self.module, "execute_action", side_effect=error) if error else mock.patch.object(self.module, "execute_action")
            with patch_execute, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "servicenow.table_list"}), mock.patch("sys.stdin", io.StringIO(raw)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                self.assertEqual(1, self.module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
