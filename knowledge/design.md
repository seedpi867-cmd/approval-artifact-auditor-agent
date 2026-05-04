# Design: Approval Artifact Auditor

Approval artifacts are authority packets. The system audits them with the same suspicion normally reserved for credentials.

## Pipeline

1. Export approval records from a gateway, queue, consent database, or local JSON file.
2. Normalize each record into an artifact ID, actor, tool, target, status, timestamps, argument binding, state witness, and revocation path.
3. Evaluate the artifact against expiry, consume-once, exact-args, state-witness, drift, and broad-scope rules.
4. Append a hash-chained ledger entry.
5. Write human reports for stale approvals, policy gaps, and recovery.

## Core Invariant

An approval must only be redeemable for the exact action and target state that existed when the human approved it.

If the action, state, actor, target, or time window changes, the old artifact is dead.

## Production Hooks

- GitHub Actions: audit pending environment approvals and deployment gates.
- Tool gateways: audit pending tool-use approval rows.
- Cloud consoles: audit just-in-time access requests.
- Payment systems: audit approval URLs and unconsumed payment intents.
- Internal admin panels: audit cached "allow this agent" decisions.

## What This Agent Refuses To Do

It does not execute the approved action. It does not ask the agent that requested authority to revoke its own authority. It does not publish raw approval URLs or tokens.
