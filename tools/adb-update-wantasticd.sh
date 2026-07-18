#!/bin/sh
set -eu

adb_bin=${ADB:-adb}
serial=${ADB_SERIAL:-}
binary=${ADB_BINARY:-bin/wantasticd-linux-arm}
remote_path=${ADB_REMOTE_PATH:-/usr/bin/wantasticd}
service=${ADB_SERVICE:-wantasticd}
stage=/data/local/tmp/wantasticd.new
backup="${remote_path}.adb-backup"

adb_cmd() {
	if [ -n "$serial" ]; then
		"$adb_bin" -s "$serial" "$@"
	else
		"$adb_bin" "$@"
	fi
}

if [ ! -f "$binary" ]; then
	echo "Built wantasticd binary not found: $binary" >&2
	exit 1
fi

if ! adb_cmd get-state >/dev/null 2>&1; then
	echo "No authorized ADB device. Set ADB_SERIAL when multiple devices are attached." >&2
	exit 1
fi

echo "Pushing wantasticd to $stage"
adb_cmd push "$binary" "$stage" >/dev/null
adb_cmd shell "chmod 0755 '$stage' && '$stage' version >/dev/null"

echo "Updating $remote_path and restarting $service"
if ! adb_cmd shell "set -e; systemctl stop '$service'; cp -p '$remote_path' '$backup'; mv '$stage' '$remote_path'; chmod 0755 '$remote_path'; systemctl start '$service'; systemctl is-active --quiet '$service'"; then
	echo "New wantasticd failed to start; restoring $backup" >&2
	adb_cmd shell "if [ -f '$backup' ]; then mv '$backup' '$remote_path'; chmod 0755 '$remote_path'; systemctl restart '$service'; fi"
	exit 1
fi

adb_cmd shell "rm -f '$backup'; '$remote_path' version; systemctl is-active '$service'"
echo "wantasticd update completed"
