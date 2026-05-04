# Stale Approvals

Ledger head: `d11a1bacf1d46c493a4ec065b23600c256319f3ee87f7baaa8a74147fa433051`

## approval-expired-002 - revoke_now
- Actor: `ops-agent`
- Tool: `cloudflare.dns.update`
- Target: `zone:example`
- critical: `expired_authority` - Artifact is still live after expiry.
- critical: `argument_drift` - Current tool arguments differ from the approved arguments.
- critical: `state_drift` - Target state changed after approval was created.
- medium: `approved_unconsumed` - Approved artifact has not been consumed or revoked.

## approval-weak-003 - revoke_now
- Actor: `maintenance-agent`
- Tool: `shell.run`
- Target: `host:production`
- critical: `missing_expiry` - Pending or approved artifact has no expiry.
- high: `not_consume_once` - Artifact is not marked consume-once.
- high: `missing_exact_args_hash` - Artifact is not bound to an exact argument hash.
- medium: `missing_state_witness` - No state witness binds the approval to target state.
- high: `raw_approval_url` - Raw approval URL is present; persist only a redacted URL or hash.
- high: `broad_scope` - Approval scope appears broad or wildcarded.
- medium: `missing_revocation_path` - No explicit revocation method is attached.

