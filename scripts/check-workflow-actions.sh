#!/usr/bin/env bash
set -euo pipefail

blocked_patterns=(
  'golang/govulncheck-action@v1'
  'actions/checkout@v4'
  'actions/checkout@v4.1.1'
  'actions/setup-go@v5'
  'actions/setup-go@v5.0.0'
)

failed=0
for pattern in "${blocked_patterns[@]}"; do
  if grep -R -n --fixed-strings "$pattern" .github/workflows; then
    echo "::error title=Deprecated GitHub Action reference::Replace $pattern with a Node.js 24-compatible action or the direct govulncheck command." >&2
    failed=1
  fi
done

exit "$failed"
