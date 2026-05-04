#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output"
LEDGER = OUTPUT / "approval-artifacts.jsonl"


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = dt.datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    return None


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_records(source: Path) -> list[dict[str, Any]]:
    files: list[Path]
    if source.is_file():
        files = [source]
    else:
        files = sorted([*source.glob("*.json"), *source.glob("*.jsonl")])

    records: list[dict[str, Any]] = []
    for path in files:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if path.suffix == ".jsonl":
            for index, line in enumerate(text.splitlines(), start=1):
                if line.strip():
                    record = json.loads(line)
                    record["_source"] = f"{path.name}:{index}"
                    records.append(record)
        else:
            data = json.loads(text)
            if isinstance(data, list):
                for index, record in enumerate(data, start=1):
                    record["_source"] = f"{path.name}:{index}"
                    records.append(record)
            else:
                data["_source"] = path.name
                records.append(data)
    return records


def has_broad_scope(record: dict[str, Any]) -> bool:
    tool = str(record.get("tool", "")).lower()
    scope = stable_json(record.get("scope", record.get("requested_args", {}))).lower()
    broad_terms = ["*", "all", "any", "shell", "admin", "write:any", "repo:*", "customer:*"]
    return any(term in tool or term in scope for term in broad_terms)


def evaluate(record: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    status = str(record.get("status", "unknown")).lower()
    created_at = parse_time(record.get("created_at"))
    expires_at = parse_time(record.get("expires_at"))
    consumed_at = parse_time(record.get("consumed_at"))
    requested_args = record.get("requested_args")
    current_args = record.get("current_args")
    witness = record.get("state_witness") or {}

    findings: list[dict[str, str]] = []

    def add(severity: str, code: str, detail: str) -> None:
        findings.append({"severity": severity, "code": code, "detail": detail})

    if status in {"pending", "approved"} and not expires_at:
        add("critical", "missing_expiry", "Pending or approved artifact has no expiry.")
    if expires_at and status in {"pending", "approved"} and expires_at < now and not consumed_at:
        add("critical", "expired_authority", "Artifact is still live after expiry.")
    if record.get("consume_once") is not True:
        add("high", "not_consume_once", "Artifact is not marked consume-once.")
    if not record.get("exact_args_hash"):
        add("high", "missing_exact_args_hash", "Artifact is not bound to an exact argument hash.")
    if requested_args is not None and current_args is not None and requested_args != current_args:
        add("critical", "argument_drift", "Current tool arguments differ from the approved arguments.")
    if not witness:
        add("medium", "missing_state_witness", "No state witness binds the approval to target state.")
    elif witness.get("requested") != witness.get("current"):
        add("critical", "state_drift", "Target state changed after approval was created.")
    if record.get("approval_url") and not record.get("approval_url_redacted", False):
        add("high", "raw_approval_url", "Raw approval URL is present; persist only a redacted URL or hash.")
    if has_broad_scope(record):
        add("high", "broad_scope", "Approval scope appears broad or wildcarded.")
    if created_at and expires_at and expires_at - created_at > dt.timedelta(hours=1):
        add("medium", "long_lived_approval", "Approval lifetime exceeds one hour.")
    if status == "approved" and not consumed_at:
        add("medium", "approved_unconsumed", "Approved artifact has not been consumed or revoked.")
    if not record.get("revocation"):
        add("medium", "missing_revocation_path", "No explicit revocation method is attached.")

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_score = max((severity_order[f["severity"]] for f in findings), default=0)
    verdict = "pass"
    if max_score >= 4:
        verdict = "revoke_now"
    elif max_score >= 3:
        verdict = "fix_before_use"
    elif max_score >= 2:
        verdict = "monitor"

    artifact_id = str(record.get("id") or record.get("approval_id") or record.get("_source", "unknown"))
    canonical = {k: v for k, v in record.items() if k not in {"approval_url"}}
    return {
        "artifact_id": artifact_id,
        "source": record.get("_source"),
        "actor": record.get("actor"),
        "tool": record.get("tool"),
        "target": record.get("target"),
        "status": status,
        "verdict": verdict,
        "findings": findings,
        "fingerprint": "sha256:" + sha256_text(stable_json(canonical)),
    }


def previous_hash() -> str:
    if not LEDGER.exists():
        return "0" * 64
    lines = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return "0" * 64
    try:
        return json.loads(lines[-1]).get("entry_hash", "0" * 64)
    except json.JSONDecodeError:
        return "0" * 64


def append_ledger(results: list[dict[str, Any]], source: Path) -> str:
    prev = previous_hash()
    entry = {
        "timestamp": utcnow().isoformat(),
        "source": str(source),
        "source_hash": file_hash(source) if source.is_file() else None,
        "records": len(results),
        "verdict_counts": {},
        "results": results,
        "prev_hash": prev,
    }
    for result in results:
        entry["verdict_counts"][result["verdict"]] = entry["verdict_counts"].get(result["verdict"], 0) + 1
    entry["entry_hash"] = sha256_text(stable_json(entry))
    with LEDGER.open("a", encoding="utf-8") as fh:
        fh.write(stable_json(entry) + "\n")
    return entry["entry_hash"]


def write_reports(results: list[dict[str, Any]], ledger_hash: str) -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    summary = {
        "generated_at": utcnow().isoformat(),
        "ledger_head": ledger_hash,
        "records": len(results),
        "verdict_counts": {},
        "critical": [r for r in results if r["verdict"] == "revoke_now"],
    }
    for result in results:
        summary["verdict_counts"][result["verdict"]] = summary["verdict_counts"].get(result["verdict"], 0) + 1
    (OUTPUT / "latest-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    stale_lines = ["# Stale Approvals", "", f"Ledger head: `{ledger_hash}`", ""]
    for result in results:
        if result["verdict"] in {"revoke_now", "fix_before_use"}:
            stale_lines.append(f"## {result['artifact_id']} - {result['verdict']}")
            stale_lines.append(f"- Actor: `{result.get('actor')}`")
            stale_lines.append(f"- Tool: `{result.get('tool')}`")
            stale_lines.append(f"- Target: `{result.get('target')}`")
            for finding in result["findings"]:
                stale_lines.append(f"- {finding['severity']}: `{finding['code']}` - {finding['detail']}")
            stale_lines.append("")
    if len(stale_lines) == 4:
        stale_lines.append("No stale or dangerous approvals found.")
    (OUTPUT / "stale-approvals.md").write_text("\n".join(stale_lines) + "\n", encoding="utf-8")

    gaps: dict[str, int] = {}
    for result in results:
        for finding in result["findings"]:
            gaps[finding["code"]] = gaps.get(finding["code"], 0) + 1
    gap_lines = ["# Policy Gaps", ""]
    if gaps:
        for code, count in sorted(gaps.items(), key=lambda item: (-item[1], item[0])):
            gap_lines.append(f"- `{code}`: {count}")
    else:
        gap_lines.append("No policy gaps found.")
    (OUTPUT / "policy-gaps.md").write_text("\n".join(gap_lines) + "\n", encoding="utf-8")

    recovery_lines = [
        "# Recovery",
        "",
        "When an approval artifact is dangerous, revoke the artifact directly. Do not ask the proposing agent to clean up its own authority.",
        "",
        "1. Delete or mark revoked in the approval store.",
        "2. Invalidate signed approval URLs and opaque IDs.",
        "3. Clear cached standing decisions for the actor, tool, and target.",
        "4. Re-read target state before creating a replacement approval.",
        "5. Append the revocation receipt to the same ledger as the original approval.",
        "",
        "Artifacts requiring immediate attention:",
    ]
    urgent = [r for r in results if r["verdict"] == "revoke_now"]
    if urgent:
        for result in urgent:
            recovery_lines.append(f"- `{result['artifact_id']}`: revoke before any execution.")
    else:
        recovery_lines.append("- None.")
    (OUTPUT / "recovery.md").write_text("\n".join(recovery_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit approval artifacts as capabilities.")
    parser.add_argument("source", nargs="?", default="samples", help="JSON/JSONL file or directory of approval records")
    args = parser.parse_args()

    source = Path(args.source)
    if not source.is_absolute():
        source = ROOT / source
    if not source.exists():
        raise SystemExit(f"source does not exist: {source}")

    OUTPUT.mkdir(parents=True, exist_ok=True)
    records = load_records(source)
    results = [evaluate(record, utcnow()) for record in records]
    ledger_hash = append_ledger(results, source)
    write_reports(results, ledger_hash)
    print(json.dumps({"records": len(results), "ledger_head": ledger_hash}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
