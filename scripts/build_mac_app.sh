#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_dir"

GOTOOLCHAIN=go1.27.2 go run github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-beta.29 \
  task darwin:package:universal \
  WANTASTIC_LDFLAGS='-extldflags=-mmacosx-version-min=13.0'

app_bundle="$repo_dir/build/bin/Wantastic.app"
echo "Built and ad-hoc signed $app_bundle"
