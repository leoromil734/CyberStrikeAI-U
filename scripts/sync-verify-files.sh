#!/usr/bin/env bash
# Sync only the files touched by this change set from the Windows workspace into
# a scratch copy on the build host. Nothing is written into the running tree.
set -euo pipefail

LOCAL_ROOT="/c/Users/test/Desktop/Code/ai-rerverse/cb-muti-rec/CyberStrikeAI-U"
REMOTE_ROOT="/tmp/csai-p1-verify"

FILES=(
  internal/config/config.go
  internal/config/config_test.go
  internal/database/database.go
  internal/database/result_artifacts.go
  internal/database/scratch_retention.go
  internal/database/result_artifacts_test.go
  internal/evidence/registry.go
  internal/evidence/types.go
  internal/scratchretention/retention.go
  internal/scratchretention/retention_test.go
  internal/app/app.go
  internal/app/result_pipeline.go
  internal/multiagent/session_context_middleware.go
  internal/multiagent/session_context_middleware_test.go
  internal/multiagent/model_output_guard_middleware.go
  internal/multiagent/model_output_guard_middleware_test.go
  internal/multiagent/runner.go
  internal/multiagent/eino_orchestration.go
  internal/multiagent/eino_single_runner.go
  internal/security/directory_discovery_probe.go
  internal/security/directory_discovery_probe_test.go
  internal/security/executor.go
  internal/mcp/execution_control_tools.go
  internal/mcp/execution_service.go
  internal/mcp/external_manager.go
  internal/mcp/server.go
  internal/recon/crtsh.go
  config.example.yaml
  scripts/crtsh-recon.py
  tools/crtsh_search.yaml
  mcp-servers/shared/proxy-pool.mjs
  mcp-servers/shared/proxy-pool.test.mjs
  mcp-servers/shared/proxy.example.json
  mcp-servers/web-search/server.mjs
)

for relative in "${FILES[@]}"; do
  target="$REMOTE_ROOT/$relative"
  mkdir -p "$(dirname "$target")"
  cp "$LOCAL_ROOT/$relative" "$target"
  echo "synced $relative"
done
