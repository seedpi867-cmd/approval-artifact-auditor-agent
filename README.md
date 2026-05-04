# approval-artifact-auditor-agent

An autonomous auditor for stale, replayable, or weakly-bound approval artifacts.

Most approval flows treat the human click as the important event. That is too late and too vague. The dangerous object is the artifact left behind: a pending approval ID, a signed URL, a cached consent, a serialized tool call, a queue row, a gateway token, a one-click "allow" decision waiting to be redeemed.

This agent watches those artifacts as capabilities.

## What It Does

`approval-artifact-auditor-agent` reads approval records from JSON files, scores each one against a strict local policy, and writes:

- an append-only hash-chained audit ledger
- a human-readable stale approval report
- a policy gap report
- a recovery playbook for revoking pending authority
- machine-readable summary JSON

It looks for:

- expired approvals still pending or already approved but unconsumed
- missing expiry
- missing consume-once protection
- missing exact argument binding
- weak or absent state witnesses
- parameter drift between requested and current tool arguments
- target drift between requested and current resource state
- reusable approval URLs and opaque IDs
- approval artifacts with broad tool scopes

## Try It

```bash
python3 tools/approval_auditor.py samples
```

Outputs are written to:

```text
output/approval-artifacts.jsonl
output/latest-summary.json
output/stale-approvals.md
output/policy-gaps.md
output/recovery.md
```

## Approval Record Format

```json
{
  "id": "approval-001",
  "actor": "deploy-agent",
  "tool": "git.push",
  "target": "repo:example/project",
  "status": "pending",
  "created_at": "2026-05-04T10:00:00Z",
  "expires_at": "2026-05-04T10:10:00Z",
  "consume_once": true,
  "exact_args_hash": "sha256:...",
  "requested_args": {"branch": "main"},
  "current_args": {"branch": "main"},
  "state_witness": {
    "kind": "git-head",
    "requested": "abc123",
    "current": "abc123"
  },
  "revocation": {
    "method": "delete_queue_row",
    "ref": "approvals/approval-001"
  }
}
```

The sample records intentionally include good and bad approvals so the first run produces visible findings.

## Why This Exists

Human approval is often treated like a magic moral event. It is not. It is a capability handoff with a half-life.

An approval made at 10:00 can become wrong at 10:03 because the branch moved, the amount changed, the resource was deleted, the user lost access, the queue item was replayed, or the agent cached a decision meant for one action and spent it on another.

This agent gives approval artifacts the same treatment serious systems give credentials: expiry, binding, consumption, logging, and revocation.

## Run As A Loop

Edit `config.sh`, then:

```bash
chmod +x brain-loop.sh
./brain-loop.sh
```

For deterministic operation, run `tools/approval_auditor.py` from cron or another loop and point it at the directory containing exported approval records.

## License

MIT
