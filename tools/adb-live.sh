#!/bin/sh
set -eu

adb_bin=${ADB:-adb}
serial=${ADB_SERIAL:-}
remote_dir=${ADB_REMOTE_DIR:-/data/local/tmp/wantasticd-test}
binary=${ADB_BINARY:-bin/wusp-device-test}
interval=${ADB_LIVE_INTERVAL:-1}
test_args=${ADB_TEST_ARGS:-}
live_once=${ADB_LIVE_ONCE:-0}

adb_cmd() {
	if [ -n "$serial" ]; then
		"$adb_bin" -s "$serial" "$@"
	else
		"$adb_bin" "$@"
	fi
}

build_push_run() {
	make adb-test-build
	adb_cmd shell mkdir -p "$remote_dir"
	# Stop the previous diagnostic before replacing its executable. This also
	# recovers cleanly from an interrupted host-side ADB session.
	adb_cmd shell "killall test 2>/dev/null || true"
	adb_cmd push "$binary" "$remote_dir/test" >/dev/null
	adb_cmd shell chmod 0755 "$remote_dir/test"
	# Word splitting is deliberate: ADB_TEST_ARGS is a list of diagnostic flags.
	adb_cmd shell "$remote_dir/test" $test_args
}

if ! adb_cmd get-state >/dev/null 2>&1; then
	echo "No authorized ADB device. Set ADB_SERIAL when more than one device is attached." >&2
	exit 1
fi

last=
while :; do
	current=$(find cmd/test internal/modem internal/wusp -type f -name '*.go' -exec stat -f '%m %N' {} \; 2>/dev/null | sort | cksum)
	if [ "$current" != "$last" ]; then
		build_push_run || true
		last=$current
		if [ "$live_once" = "1" ]; then
			exit 0
		fi
	fi
	sleep "$interval"
done
