#!/bin/sh
set -eu

adb_bin=${ADB:-adb}
serial=${ADB_SERIAL:-}
binary=${ADB_BINARY:-bin/wantasticd-linux-arm}
remote_path=${ADB_REMOTE_PATH:-/usr/bin/wantasticd}
service=${ADB_SERVICE:-wantasticd}
config_path=${ADB_CONFIG_PATH:-/etc/wantastic}
stage=/data/local/tmp/wantasticd.new
backup="${remote_path}.adb-backup"
unit_path="/etc/systemd/system/${service}.service"
init_path="/etc/init.d/${service}"

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

if adb_cmd shell "command -v systemctl >/dev/null 2>&1 && { [ -d /run/systemd/system ] || [ -S /run/systemd/private ]; }"; then
	service_manager=systemd
	echo "Ensuring systemd unit $unit_path"
	adb_cmd shell "mkdir -p /etc/systemd/system || exit 1; if [ ! -f '$unit_path' ] || ! grep -Fqx 'ExecStart=$remote_path connect --config $config_path' '$unit_path'; then printf '%s\n' '[Unit]' 'Description=Wantastic Overlay Networking Daemon' 'After=network-online.target' 'Wants=network-online.target' '' '[Service]' 'Type=simple' 'ExecStart=$remote_path connect --config $config_path' 'Restart=on-failure' 'RestartSec=5' 'KillMode=process' '' '[Install]' 'WantedBy=multi-user.target' > '$unit_path' || exit 1; fi; chmod 0644 '$unit_path' || exit 1; systemctl daemon-reload || exit 1; systemctl enable '$service' >/dev/null || exit 1"
else
	service_manager=initd
	echo "Ensuring init service $init_path"
	adb_cmd shell "mkdir -p /etc/init.d || exit 1; if [ ! -f '$init_path' ] || ! grep -Fqx 'DAEMON=$remote_path' '$init_path'; then printf '%s\n' '#!/bin/sh' 'DAEMON=$remote_path' 'CONFIG=$config_path' 'PIDFILE=/var/run/$service.pid' 'LOGFILE=/var/log/$service.log' '' 'is_running() { [ -s \"\$PIDFILE\" ] && kill -0 \"\$(cat \"\$PIDFILE\")\" 2>/dev/null; }' 'case \"\$1\" in' '  start)' '    is_running && exit 0' '    if command -v start-stop-daemon >/dev/null 2>&1; then' '      start-stop-daemon -S -b -m -p \"\$PIDFILE\" -x \"\$DAEMON\" -- connect --config \"\$CONFIG\"' '    else' '      \"\$DAEMON\" connect --config \"\$CONFIG\" >>\"\$LOGFILE\" 2>&1 &' '      echo \$! > \"\$PIDFILE\"' '    fi' '    ;;' '  stop)' '    if command -v start-stop-daemon >/dev/null 2>&1; then start-stop-daemon -K -p \"\$PIDFILE\" 2>/dev/null || true; elif is_running; then kill \"\$(cat \"\$PIDFILE\")\"; fi' '    rm -f \"\$PIDFILE\"' '    ;;' '  restart)' '    \"\$0\" stop; \"\$0\" start' '    ;;' '  status)' '    is_running' '    ;;' '  *) echo \"Usage: \$0 {start|stop|restart|status}\" >&2; exit 2 ;;' 'esac' > '$init_path' || exit 1; fi; chmod 0755 '$init_path' || exit 1; if command -v rc-update >/dev/null 2>&1; then rc-update add '$service' default >/dev/null 2>&1 || true; elif command -v update-rc.d >/dev/null 2>&1; then update-rc.d '$service' defaults >/dev/null 2>&1 || true; fi"
fi

echo "Updating $remote_path and restarting $service"
if [ "$service_manager" = systemd ]; then
	update_command="systemctl stop '$service' || exit 1; killall wantasticd 2>/dev/null || true; cp -p '$remote_path' '$backup' || exit 1; mv '$stage' '$remote_path' || exit 1; chmod 0755 '$remote_path' || exit 1; systemctl start '$service' || exit 1; state=\$(systemctl is-active '$service'); [ \"\$state\" = active ] || exit 1"
	restore_command="systemctl daemon-reload; systemctl restart '$service'"
	verify_command="state=\$(systemctl is-active '$service'); [ \"\$state\" = active ] || exit 1; echo \"\$state\""
else
	update_command="'$init_path' stop || true; killall wantasticd 2>/dev/null || true; cp -p '$remote_path' '$backup' || exit 1; mv '$stage' '$remote_path' || exit 1; chmod 0755 '$remote_path' || exit 1; '$init_path' start || exit 1; sleep 1; '$init_path' status || exit 1"
	restore_command="'$init_path' restart"
	verify_command="'$init_path' status || exit 1; echo active"
fi

if ! adb_cmd shell "$update_command"; then
	echo "New wantasticd failed to start; restoring $backup" >&2
	adb_cmd shell "if [ -f '$backup' ]; then mv '$backup' '$remote_path'; chmod 0755 '$remote_path'; $restore_command; fi"
	exit 1
fi

adb_cmd shell "'$remote_path' version; $verify_command; rm -f '$backup'"
echo "wantasticd update completed"
