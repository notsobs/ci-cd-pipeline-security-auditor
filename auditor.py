"""Offline CI/CD configuration auditor. Never executes scanned configurations."""
import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote
import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

VERSION = "1.0.0"
LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_BYTES = 2 * 1024 * 1024
RULES = {
    "SEC001": ("high", "Suspected hardcoded credential", "Use a secret-store reference. Rotate real credentials if exposed."),
    "PIN001": ("medium", "Mutable external action or workflow reference", "Pin to a reviewed full 40-character commit SHA; maintain updates."),
    "PIN002": ("medium", "Mutable container reference", "Pin the container to a reviewed sha256 image digest."),
    "INJ001": ("high", "Untrusted expression inside a shell script", "Pass input through an environment variable, quote its expansion, and avoid eval."),
    "PERM001": ("high", "Token requests write-all permissions", "Default to contents: read and grant only required permissions per job."),
    "PERM002": ("medium", "Sensitive token write permission", "Review this grant and restrict it to jobs that require it."),
    "PERM003": ("low", "Workflow token permissions are implicit", "Declare workflow-level permissions; repository defaults are unknown offline."),
    "TRUST001": ("critical", "Privileged trigger checks out pull-request-controlled code", "Use unprivileged pull_request jobs for untrusted code; separate privileged operations."),
    "RUN001": ("medium", "Pull-request workflow uses a self-hosted runner", "Use isolated disposable runners for untrusted code; review runner access policies."),
}
SENSITIVE = re.compile(r"(?:^|[_-])(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)(?:$|[_-])", re.I)
CREDENTIAL = re.compile(r"(?:\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bAKIA[A-Z0-9]{16}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
ASSIGNMENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*(?:\"([^\"\n]*)\"|'([^'\n]*)'|([^\s;#]+))")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
UNTRUSTED = re.compile(r"\b(?:github\.(?:event\.(?:pull_request\.(?:title|body|head\.(?:ref|label|repo\.full_name))|(?:issue|comment|review|discussion)\.(?:title|body)|(?:head_commit|commits)\b|inputs\b)|head_ref)|inputs\b)", re.I)

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    column: int
    title: str
    remediation: str

class InputError(Exception):
    def __init__(self, message, line=1):
        super().__init__(message)
        self.line = line

def scalar(node):
    return node.value if isinstance(node, ScalarNode) else ""

def fields(node):
    return {scalar(k): v for k, v in node.value} if isinstance(node, MappingNode) else {}

def children(node):
    if isinstance(node, MappingNode):
        return [v for _, v in node.value]
    return node.value if isinstance(node, SequenceNode) else []

def literals(node):
    if isinstance(node, ScalarNode):
        yield node
    else:
        for child in children(node):
            yield from literals(child)

def is_reference(value):
    value = value.strip()
    return not value or bool(re.fullmatch(r"\$\{\{.*?\}\}|\$\([A-Za-z_][A-Za-z0-9_.-]*\)|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})|%[A-Za-z_][A-Za-z0-9_]*%", value, re.S))

def parse_document(text):
    try:
        # Reject aliases before composition: no cycles or expansion ambiguity.
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.events.AliasEvent):
                raise InputError("YAML aliases are unsupported; expand the referenced value.", event.start_mark.line + 1)
        node = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        # Parser exception strings can expose credential-bearing source.
        raise InputError("Invalid YAML or multiple YAML documents.", mark.line + 1 if mark else 1) from None
    if not isinstance(node, MappingNode):
        raise InputError("Configuration must contain a YAML mapping.")
    def validate(current, depth=0):
        if depth > 80:
            raise InputError("YAML nesting exceeds the supported limit.", current.start_mark.line + 1)
        if current.tag not in {"tag:yaml.org,2002:" + t for t in ("map", "seq", "str", "int", "float", "bool", "null", "timestamp")}:
            raise InputError("Unsupported YAML tag or merge key.", current.start_mark.line + 1)
        if isinstance(current, MappingNode):
            seen = set()
            for key, value in current.value:
                if not isinstance(key, ScalarNode) or key.value == "<<":
                    raise InputError("Complex mapping keys and YAML merges are unsupported.", key.start_mark.line + 1)
                if key.value in seen:
                    raise InputError("Duplicate YAML mapping key.", key.start_mark.line + 1)
                seen.add(key.value)
                validate(key, depth + 1)
                validate(value, depth + 1)
        elif isinstance(current, SequenceNode):
            for child in current.value:
                validate(child, depth + 1)
    validate(node)
    return node

def normalize_expression(value):
    # Normalize literal bracket property access and whitespace, but do not evaluate.
    value = re.sub(r"\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]", r".\1", value)
    return re.sub(r"\s+", "", value)


def audit_document(node, filename, kind="github"):
    findings, seen = [], set()
    def emit(rule, location):
        severity, title, fix = RULES[rule]
        key = (rule, location.start_mark.line + 1, location.start_mark.column + 1)
        if key not in seen:
            seen.add(key)
            findings.append(Finding(rule, severity, filename, key[1], key[2], title, fix))
    def secrets(current, permission_map=False):
        if isinstance(current, MappingNode):
            for key, value in current.value:
                if kind == "github" and scalar(key) == "secrets" and scalar(value) == "inherit" and "uses" in fields(current):
                    continue
                if permission_map and scalar(key) == "id-token" and scalar(value) in {"read", "write", "none"}:
                    continue
                if SENSITIVE.search(scalar(key)) and isinstance(value, ScalarNode) and not is_reference(value.value):
                    emit("SEC001", value)
                secrets(value, kind == "github" and scalar(key) == "permissions")
        elif isinstance(current, SequenceNode):
            for child in current.value:
                secrets(child)
        elif isinstance(current, ScalarNode):
            if CREDENTIAL.search(current.value):
                emit("SEC001", current)
            for match in ASSIGNMENT.finditer(current.value):
                value = next((v for v in match.groups()[1:] if v is not None), "")
                if SENSITIVE.search(match.group(1)) and not is_reference(value):
                    if not value.startswith("$" + "{{"):
                        emit("SEC001", current)
    secrets(node)
    if kind == "generic":
        return findings
    top = fields(node)
    jobs = top.get("jobs")
    if not isinstance(jobs, MappingNode) or not jobs.value:
        raise InputError("GitHub workflow requires a non-empty jobs mapping; use --kind generic for other YAML.")
    trigger = top.get("on")
    if trigger is None or not isinstance(trigger, (ScalarNode, MappingNode, SequenceNode)) or not trigger.value:
        raise InputError("GitHub workflow requires a non-empty on trigger.")
    if isinstance(trigger, MappingNode):
        events = set(fields(trigger))
    elif isinstance(trigger, SequenceNode):
        events = {scalar(x) for x in trigger.value}
    else:
        events = {scalar(trigger)}
    privileged = bool(events & {"pull_request_target", "workflow_run"})
    def permissions(current):
        if not isinstance(current, MappingNode) and scalar(current) not in {"read-all", "write-all"}:
            raise InputError("Permissions must be a mapping, read-all, or write-all.", current.start_mark.line + 1)
        for value in fields(current).values():
            if scalar(value) not in {"read", "write", "none"}:
                raise InputError("Permission values must be read, write, or none.", value.start_mark.line + 1)
        if scalar(current) == "write-all":
            emit("PERM001", current)
        for name, value in fields(current).items():
            if scalar(value) == "write" and name in {"contents", "packages", "actions", "id-token", "security-events", "pull-requests"}:
                emit("PERM002", value)
    if "permissions" in top:
        permissions(top["permissions"])
    else:
        emit("PERM003", node)
    def pin(value):
        ref = scalar(value)
        if not ref:
            raise InputError("Action or workflow reference cannot be empty.", value.start_mark.line + 1)
        if ref.startswith("./"):
            return
        if ref.startswith("docker://"):
            if not re.fullmatch(r"docker://[^\s@]+@sha256:[a-fA-F0-9]{64}", ref):
                emit("PIN002", value)
        elif not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s@]+)*@[a-fA-F0-9]{40}", ref):
            emit("PIN001", value)
    for _, job in jobs.value:
        if not isinstance(job, MappingNode):
            raise InputError("Each job must be a mapping.", job.start_mark.line + 1)
        job_fields = fields(job)
        if "permissions" in job_fields:
            permissions(job_fields["permissions"])
        if "uses" in job_fields:
            if not isinstance(job_fields["uses"], ScalarNode):
                raise InputError("Reusable workflow reference must be a scalar.", job.start_mark.line + 1)
            pin(job_fields["uses"])
        runners = job_fields.get("runs-on")
        if events & {"pull_request", "pull_request_target"} and runners:
            if any(re.search(r"\bself-hosted\b", n.value) for n in literals(runners)):
                emit("RUN001", runners)
        steps = job_fields.get("steps")
        if steps is None:
            if "uses" not in job_fields:
                raise InputError("Each job requires steps or a reusable workflow reference.", job.start_mark.line + 1)
            continue
        if not isinstance(steps, SequenceNode) or not steps.value:
            raise InputError("Job steps must be a non-empty sequence.", steps.start_mark.line + 1)
        for step in steps.value:
            if not isinstance(step, MappingNode):
                raise InputError("Each step must be a mapping.", step.start_mark.line + 1)
            step_fields = fields(step)
            action = step_fields.get("uses")
            if action is not None:
                if not isinstance(action, ScalarNode):
                    raise InputError("Action reference must be a scalar.", action.start_mark.line + 1)
                pin(action)
            run = step_fields.get("run")
            if run is not None:
                if not isinstance(run, ScalarNode):
                    raise InputError("Step run must be a scalar.", run.start_mark.line + 1)
                if any(UNTRUSTED.search(normalize_expression(m.group(1))) for m in EXPRESSION.finditer(run.value)):
                    emit("INJ001", run)
            if privileged and scalar(action).split("@", 1)[0].lower() == "actions/checkout":
                inputs = fields(step_fields.get("with"))
                for key in ("ref", "repository"):
                    value = inputs.get(key)
                    if value and re.search(r"github\s*\.\s*event\s*\.\s*pull_request\b|refs/pull/", normalize_expression(scalar(value))):
                        emit("TRUST001", value)
    return sorted(findings, key=lambda f: (f.line, f.column, f.rule_id))

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", ".venv314", "venv"}

def discover(targets):
    files, errors = set(), []
    for raw in targets:
        target = Path(raw)
        if target.is_symlink():
            errors.append({"file": str(target), "line": 1, "message": "Symlink targets are unsupported."})
        elif target.is_file():
            files.add(target.absolute())
        elif target.is_dir():
            def walk_error(error):
                errors.append({"file": str(target), "line": 1, "message": "Cannot access part of this directory."})
            for base, dirs, names in os.walk(target, followlinks=False, onerror=walk_error):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".venv") and not Path(base, d).is_symlink())
                for name in names:
                    candidate = Path(base, name)
                    if candidate.suffix.lower() in {".yaml", ".yml"}:
                        if candidate.is_symlink():
                            errors.append({"file": str(candidate), "line": 1, "message": "Symlink files are unsupported."})
                        else:
                            files.add(candidate.absolute())
        else:
            errors.append({"file": str(target), "line": 1, "message": "Input does not exist or cannot be read."})
    if not files and not errors:
        errors.append({"file": ", ".join(map(str, targets)), "line": 1, "message": "No YAML files found; no audit was performed."})
    return sorted(files), errors

def display_path(file):
    try:
        return file.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return file.as_posix()

def scan(targets, kind="github"):
    files, errors = discover(targets)
    findings, scanned = [], []
    for file in files:
        name = display_path(file)
        try:
            with file.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise InputError("File exceeds 2 MiB limit.")
            node = parse_document(raw.decode("utf-8-sig"))
            findings.extend(audit_document(node, name, kind))
            scanned.append(name)
        except InputError as error:
            errors.append({"file": name, "line": error.line, "message": str(error)})
        except (OSError, UnicodeError, RecursionError):
            errors.append({"file": name, "line": 1, "message": "Cannot read this UTF-8 configuration or nesting exceeds parser limits."})
    return {"tool": "pipeline-auditor", "version": VERSION, "kind": kind, "files_scanned": scanned,
            "findings": [asdict(f) for f in findings], "errors": errors,
            "coverage": "GitHub Actions rules and YAML secret heuristics" if kind == "github" else "YAML secret heuristics only; no platform-specific checks"}

def sarif(report):
    results = []
    for f in report["findings"]:
        results.append({"ruleId": f["rule_id"], "level": "note" if f["severity"] == "low" else "warning" if f["severity"] == "medium" else "error",
            "message": {"text": f["title"] + ". " + f["remediation"]}, "properties": {"severity": f["severity"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote(f["file"], safe="/:.")},
                "region": {"startLine": f["line"], "startColumn": f["column"]}}}]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": report["tool"], "version": VERSION, "rules": [
            {"id": rule, "shortDescription": {"text": data[1]}, "help": {"text": data[2]}} for rule, data in RULES.items()]}},
        "invocations": [{"executionSuccessful": not report["errors"], "toolExecutionNotifications": [
            {"level": "error", "message": {"text": e["message"]}} for e in report["errors"]]}],
        "results": results}]}

def clean_text(value):
    return str(value).encode("unicode_escape").decode("ascii")

def render(report, format):
    if format == "json":
        return json.dumps(report, indent=2)
    if format == "sarif":
        return json.dumps(sarif(report), indent=2)
    lines = ["CI/CD Pipeline Security Auditor " + VERSION, "Coverage: " + report["coverage"]]
    for f in report["findings"]:
        lines.extend([f'[{f["severity"].upper()}] {f["rule_id"]} {clean_text(f["file"])}:{f["line"]}:{f["column"]} - {f["title"]}', "  Fix: " + f["remediation"]])
    for e in report["errors"]:
        lines.append(f'[ERROR] {clean_text(e["file"])}:{e["line"]} - {e["message"]}')
    lines.append(f'Files scanned: {len(report["files_scanned"])} | Findings: {len(report["findings"])} | Errors: {len(report["errors"])}')
    return "\n".join(lines)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*", default=[".github/workflows"], help="YAML files or directories (default: .github/workflows)")
    parser.add_argument("--kind", choices=["github", "generic"], default="github", help="Generic mode checks YAML for suspected secrets only")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--output", type=Path, help="Write report to this file")
    parser.add_argument("--fail-on", choices=[*LEVELS, "none"], default="medium", help="Minimum severity to fail (errors always exit 2)")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    report = scan(args.targets, args.kind)
    result = render(report, args.format) + "\n"
    if args.output:
        try:
            inputs, _ = discover(args.targets)
            if args.output.is_symlink() or args.output.resolve() in {f.resolve() for f in inputs}:
                raise OSError("Output collides with an input")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(result, encoding="utf-8")
        except OSError:
            print("[ERROR] Cannot write report; choose a writable output distinct from input files.", file=sys.stderr)
            return 2
    else:
        print(result, end="")
    if report["errors"]:
        return 2
    return int(args.fail_on != "none" and any(LEVELS[f["severity"]] >= LEVELS[args.fail_on] for f in report["findings"]))

if __name__ == "__main__":
    raise SystemExit(main())
