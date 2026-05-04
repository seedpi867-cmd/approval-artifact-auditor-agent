#!/bin/bash

AGENT_NAME="approval-artifact-auditor-agent"
SLEEP_SECONDS=300
MAX_TIMEOUT=1800
CYCLE_LOG_KEEP=50

# Override with any CLI that accepts a prompt as a single argument.
LLM_CMD="${LLM_CMD:-codex exec --dangerously-bypass-approvals-and-sandbox}"
