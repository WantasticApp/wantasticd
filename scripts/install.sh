#!/bin/sh
# Compatibility entrypoint. Keep installation policy in the repository-root
# install.sh so service supervision, version verification, and platform support
# cannot drift between two scripts.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CANONICAL_INSTALLER="$SCRIPT_DIR/../install.sh"

if [ -x "$CANONICAL_INSTALLER" ]; then
  exec "$CANONICAL_INSTALLER" "$@"
fi

echo "Error: canonical installer not found at $CANONICAL_INSTALLER" >&2
exit 1
