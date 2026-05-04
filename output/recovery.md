# Recovery

When an approval artifact is dangerous, revoke the artifact directly. Do not ask the proposing agent to clean up its own authority.

1. Delete or mark revoked in the approval store.
2. Invalidate signed approval URLs and opaque IDs.
3. Clear cached standing decisions for the actor, tool, and target.
4. Re-read target state before creating a replacement approval.
5. Append the revocation receipt to the same ledger as the original approval.

Artifacts requiring immediate attention:
- `approval-expired-002`: revoke before any execution.
- `approval-weak-003`: revoke before any execution.
