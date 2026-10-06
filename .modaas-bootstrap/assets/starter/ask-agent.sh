#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# ask-agent.sh <agent> "<question>" [--cid X] [--traceparent TP]
#
# Shell wrapper around ask_agent.py. Resolves the agent's runtime ARN from
# its AgentConfig, mints a correlation id, sends the question through
# InvokeAgentRuntime, and prints the result.
#
# Exit 0 on success or governed refusal. Non-zero on transport/permission failure.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$HERE/ask_agent.py" "$@"
