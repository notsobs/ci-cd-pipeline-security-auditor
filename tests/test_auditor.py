"""Behavioral regression tests; all credentials are synthetic."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import auditor

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
EXPR = "$" + "{{ github.event.pull_request.title }}"


def workflow(steps="      - run: echo ok\n", event="pull_request", permissions="permissions: {contents: read}\n"):
    return f"on: {event}\n{permissions}jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"


def findings(text, kind="github"):
    return auditor.audit_document(auditor.parse_document(text), "test.yml", kind)


def ids(text, kind="github"):
    return {f.rule_id for f in findings(text, kind)}


class DetectionTests(unittest.TestCase):
    def test_original_fixture_has_four_distinct_rules(self):
        report = auditor.scan([ROOT / "examples/insecure.yml"])
        self.assertFalse(report["errors"])
        self.assertEqual({f["rule_id"] for f in report["findings"]}, {"SEC001", "PIN001", "INJ001", "PERM001"})
        self.assertEqual(len(report["findings"]), 4)

    def test_corrected_fixtures_are_clean(self):
        report = auditor.scan([ROOT / "examples/secure.yml", ROOT / "examples/advanced-secure.yml"])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["errors"], [])

    def test_own_ci_is_clean(self):
        report = auditor.scan([ROOT / ".github/workflows"])
        self.assertFalse(report["errors"])
        self.assertFalse(report["findings"])

    def test_tags_and_branches_flagged(self):
        for ref in ("main", "v4", "a" * 39, "g" * 40):
            with self.subTest(ref=ref):
                self.assertIn("PIN001", ids(workflow(f"      - uses: owner/action@{ref}\n")))

    def test_full_sha_and_local_action(self):
        self.assertNotIn("PIN001", ids(workflow(f"      - uses: owner/action@{SHA}\n      - uses: ./local-action\n")))

    def test_reusable_workflow(self):
        for ref, expected in [("main", True), (SHA, False)]:
            text = f"on: push\npermissions: {{}}\njobs:\n  build:\n    uses: owner/repo/.github/workflows/build.yml@{ref}\n"
            self.assertEqual("PIN001" in ids(text), expected)

    def test_reusable_inherit_is_not_a_literal_secret(self):
        text = f"on: push\npermissions: {{}}\njobs:\n  build:\n    uses: owner/repo/.github/workflows/build.yml@{SHA}\n    secrets: inherit\n"
        self.assertNotIn("SEC001", ids(text))

    def test_container_digest(self):
        for ref, expected in [("alpine:latest", True), ("alpine@sha256:" + "b" * 64, False)]:
            self.assertEqual("PIN002" in ids(workflow(f"      - uses: docker://{ref}\n")), expected)

    def test_hardcoded_fields(self):
        for name in ("DEPLOY_PASSWORD", "API_KEY", "ACCESS_TOKEN", "PRIVATE_KEY"):
            with self.subTest(name=name):
                self.assertIn("SEC001", ids(f"{name}: fake-value\n", "generic"))

    def test_reference_fields_are_not_literals(self):
        for value in ("'" + "$" + "{{ secrets.TOKEN }}'", "'$TOKEN'", "'" + "$" + "{TOKEN}'", "'$(TOKEN)'", "'help'" ):
            text = f"TOKEN: {value}\n"
            self.assertEqual("SEC001" in ids(text, "generic"), value == "'help'")

    def test_recognizable_token_in_unrelated_field(self):
        self.assertIn("SEC001", ids("description: ghp_" + "X" * 36 + "\n", "generic"))

    def test_private_key_header(self):
        self.assertIn("SEC001", ids('data: "-----BEGIN PRIVATE KEY-----"\n', "generic"))

    def test_script_assignment(self):
        self.assertIn("SEC001", ids(workflow('      - run: export API_TOKEN="synthetic-value"\n')))

    def test_comments_are_ignored(self):
        self.assertNotIn("SEC001", ids(workflow() + "# API_TOKEN: synthetic-value\n"))

    def test_direct_injection_and_safe_env(self):
        self.assertIn("INJ001", ids(workflow(f'      - run: echo "{EXPR}"\n')))
        safe = f'      - run: printf "%s" "$TITLE"\n        env:\n          TITLE: {EXPR}\n'
        self.assertNotIn("INJ001", ids(workflow(safe)))

    def test_bracket_and_whitespace_injection(self):
        for expression in ("github['event']['pull_request']['title']", "github . event . pull_request . title", "inputs['command']"):
            expression = "$" + "{{ " + expression + " }}"
            self.assertIn("INJ001", ids(workflow(f'      - run: echo "{expression}"\n')))

    def test_bracket_privileged_checkout(self):
        expression = "$" + "{{ github['event']['pull_request']['head']['sha'] }}"
        steps = f"      - uses: actions/checkout@{SHA}\n        with:\n          ref: {expression}\n"
        self.assertIn("TRUST001", ids(workflow(steps, event="pull_request_target")))

    def test_input_expression(self):
        expression = "$" + "{{ inputs.command }}"
        self.assertIn("INJ001", ids(workflow(f'      - run: echo "{expression}"\n')))

    def test_oidc_permission_is_not_a_credential(self):
        result = ids(workflow(permissions="permissions: {id-token: write, contents: read}\n"))
        self.assertIn("PERM002", result)
        self.assertNotIn("SEC001", result)

    def test_partial_scan_errors_fail_closed(self):
        report = auditor.scan([ROOT / "examples/insecure.yml", ROOT / "missing-fixture.yml"])
        self.assertTrue(report["findings"])
        self.assertTrue(report["errors"])

    def test_permission_severities(self):
        self.assertIn("PERM001", ids(workflow(permissions="permissions: write-all\n")))
        self.assertIn("PERM002", ids(workflow(permissions="permissions: {contents: write}\n")))
        self.assertIn("PERM003", ids(workflow(permissions="")))
        self.assertNotIn("PERM003", ids(workflow(permissions="permissions: {}\n")))

    def test_privileged_pr_checkout(self):
        expr = "$" + "{{ github.event.pull_request.head.sha }}"
        steps = f"      - uses: actions/checkout@{SHA}\n        with:\n          ref: {expr}\n"
        for event in ("pull_request_target", "[push, pull_request_target]", "{pull_request_target: null}", "workflow_run"):
            self.assertIn("TRUST001", ids(workflow(steps, event=event)))
        self.assertNotIn("TRUST001", ids(workflow(steps)))

    def test_self_hosted_pull_request(self):
        text = workflow().replace("ubuntu-latest", "[self-hosted, linux]")
        self.assertIn("RUN001", ids(text))
        self.assertNotIn("RUN001", ids(text.replace("pull_request", "push")))

    def test_locations_and_no_config_values(self):
        text = workflow('      - uses: owner/action@main\n')
        finding = findings(text)[0]
        self.assertEqual(text.splitlines()[finding.line - 1].strip(), "- uses: owner/action@main")
        secret = "unique-synthetic-value-for-redaction-test"
        result = findings("TOKEN: " + secret + "\n", "generic")
        report = {"tool": "pipeline-auditor", "coverage": "test", "findings": [auditor.asdict(x) for x in result], "errors": [], "files_scanned": ["test.yml"]}
        for format in ("text", "json", "sarif"):
            self.assertNotIn(secret, auditor.render(report, format))

    def test_generic_mode_labels_limited_coverage(self):
        report = auditor.scan([ROOT / "examples/generic/gitlab-insecure.yml"], "generic")
        self.assertEqual({f["rule_id"] for f in report["findings"]}, {"SEC001"})
        self.assertIn("only", report["coverage"])
        self.assertEqual(auditor.scan([ROOT / "examples/generic/gitlab-secure.yml"], "generic")["findings"], [])


class InputSafetyTests(unittest.TestCase):
    def test_unsupported_documents(self):
        for text in ("", "[]", "x: [", "x: 1\nx: 2\n", "x: &a [*a]", "x: !!python/object:os.system {}", "a: 1\n---\nb: 2", "x: {<<: {a: b}}"):
            with self.subTest(text=text):
                with self.assertRaises(auditor.InputError):
                    auditor.parse_document(text)

    def test_malformed_workflow_shapes(self):
        for text in ("jobs: []", "jobs: {build: null}", "jobs: {build: {steps: null}}", "jobs: {build: {steps: [null]}}", "jobs: {build: {steps: [{run: []}]}}", "jobs: {build: {steps: [{uses: []}]}}"):
            with self.subTest(text=text):
                with self.assertRaises(auditor.InputError):
                    findings(text)

    def test_invalid_permissions_and_empty_steps(self):
        for text in (workflow(permissions="permissions: false\n"), workflow(permissions="permissions: {contents: banana}\n"), workflow(steps=""), workflow().replace("on: pull_request\n", "")):
            with self.subTest(text=text):
                with self.assertRaises(auditor.InputError):
                    findings(text)

    def test_error_does_not_echo_source(self):
        secret = "unique-parser-error-secret"
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "bad.yml"
            file.write_text('TOKEN: "' + secret, encoding="utf-8")
            result = auditor.scan([file])
            self.assertTrue(result["errors"])
            for format in ("text", "json", "sarif"):
                self.assertNotIn(secret, auditor.render(result, format))

    def test_nested_document_limit(self):
        with self.assertRaises(auditor.InputError):
            auditor.parse_document("x: " + "[" * 90 + "0" + "]" * 90)

    def test_utf8_bom_and_invalid_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "data.yml"
            file.write_bytes(b"\xef\xbb\xbf" + workflow().encode())
            self.assertFalse(auditor.scan([file])["errors"])
            file.write_bytes(b"\xff\xfe")
            self.assertTrue(auditor.scan([file])["errors"])

    def test_file_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "large.yml"
            file.write_bytes(b"x" * (auditor.MAX_BYTES + 1))
            self.assertIn("2 MiB", auditor.scan([file])["errors"][0]["message"])

    def test_missing_and_empty_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(auditor.scan([directory])["errors"])
            self.assertTrue(auditor.scan([Path(directory) / "missing.yml"])["errors"])

    def test_directory_scan_deduplicates_and_skips_environments(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            file = base / "good.yml"
            file.write_text(workflow(), encoding="utf-8")
            (base / ".venv314").mkdir()
            (base / ".venv314" / "bad.yml").write_text("invalid", encoding="utf-8")
            report = auditor.scan([base, file])
            self.assertEqual(len(report["files_scanned"]), 1)
            self.assertFalse(report["errors"])


class CliTests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "auditor.py"), *map(str, args)], cwd=ROOT, capture_output=True, text=True, timeout=15)

    def test_fail_thresholds(self):
        insecure = ROOT / "examples/insecure.yml"
        for threshold, code in (("low", 1), ("medium", 1), ("high", 1), ("critical", 0), ("none", 0)):
            with self.subTest(threshold=threshold):
                self.assertEqual(self.cli(insecure, "--fail-on", threshold).returncode, code)
        self.assertEqual(self.cli(ROOT / "examples/secure.yml").returncode, 0)

    def test_errors_fail_even_with_none(self):
        result = self.cli("missing-test-file.yml", "--fail-on", "none", "--format", "json")
        self.assertEqual(result.returncode, 2)
        self.assertTrue(json.loads(result.stdout)["errors"])

    def test_json_and_sarif_output(self):
        for format in ("json", "sarif"):
            result = self.cli(ROOT / "examples/insecure.yml", "--format", format)
            self.assertEqual(result.returncode, 1)
            data = json.loads(result.stdout)
            if format == "sarif":
                self.assertEqual(data["version"], "2.1.0")
                self.assertEqual(len(data["runs"][0]["results"]), 4)
                self.assertTrue(data["runs"][0]["invocations"][0]["executionSuccessful"])
            else:
                self.assertEqual(len(data["findings"]), 4)

    def test_output_file_and_input_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "input.yml"
            file.write_text(workflow(), encoding="utf-8")
            output = Path(directory) / "reports" / "scan.json"
            self.assertEqual(self.cli(file, "--format", "json", "--output", output).returncode, 0)
            self.assertEqual(json.loads(output.read_text())["findings"], [])
            before = file.read_bytes()
            self.assertEqual(self.cli(file, "--output", file).returncode, 2)
            self.assertEqual(file.read_bytes(), before)

    def test_default_target_and_help(self):
        self.assertEqual(self.cli().returncode, 0)
        self.assertEqual(self.cli("--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
