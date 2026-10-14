#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_dir"

GOTOOLCHAIN=go1.27.2 go run github.com/wailsapp/wails/v2/cmd/wails@v2.15.0 \
  build -clean -platform darwin/universal \
  -ldflags "-extldflags=-mmacosx-version-min=13.0"

echo "Built $repo_dir/build/bin/Wantastic.app"
