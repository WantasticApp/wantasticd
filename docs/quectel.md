# Quectel RM520N-GL USP device adaptation

This document records facts verified on the live target on 2026-07-18. It is
an implementation note for the USP/TR-181 backend, not a second management
interface. Controllers continue to read parameters with USP `Get`, write
writable parameters with USP `Set`, and invoke modem actions with USP
`Operate`.

Subscriber identifiers are intentionally omitted. They must only be returned
through their defined USP parameters and must never be written to logs or
documentation.

## Verified platform

| Property | Live value |
|---|---|
| Module | Quectel RM520N-GL |
| Modem firmware | `RM520NGLAAR01A08M4G` |
| SoC / board | Qualcomm SDXLEMUR MTP MBB PCIe-EP V2 |
| CPU | 32-bit ARMv7 Cortex-A7-compatible (`armv7l`, NEON/VFPv4) |
| Kernel | Linux `5.4.180-perf`, PREEMPT |
| Distribution | QTI Linux reference `LE.UM.5.3.2.r1-06300-SDX65.0` |
| Init | systemd |
| Root filesystem | UBIFS, approximately 100 MiB |
| Writable data filesystem | `/dev/ubi2_0`, mounted at `/usrdata`, `/data`, `/etc`, `/opt`, and related paths |
| RAM / swap | approximately 179 MiB RAM and 89 MiB swap |
| Device binary target | `GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0` |

## Native facilities and precedence

The adaptation must prefer facilities already supplied by the device in this
order:

1. Qualcomm/Quectel QMI and location libraries for their corresponding native
   services when a compatible build can link against the device SDK.
2. The vendor-managed AT bridge at `/dev/ttyOUT2`, invoked through the existing
   `get_atcommand` bridge. This bridge is safe to use without taking ownership
   away from `atfwd_daemon`.
3. Kernel sysfs/procfs and standard `ip`/iptables state for interface counters,
   addresses, routes, and firewall runtime state.
4. Direct modem character devices only as a last resort on variants without the
   vendor bridge.

Do not open `/dev/at_mdm0` or `/dev/at_usb0` as the normal backend. They are
owned by `atfwd_daemon`; competing access blocks or corrupts command replies.
`/dev/at_usb1` and `/dev/at_usb2` are not reliable management endpoints on this
image. The PTY bridge is `/dev/ttyOUT2 -> /dev/pts/4`.

The native libraries verified on the image include:

- QMI/QRTR: `libqmi`, `libqmi_cci`, `libqmi_client_helper`,
  `libqmi_client_qmux`, `libqmiservices`, and `libqrtr`.
- Data/QCMAP: `libdsi_netctrl`, `libnetmgr`, `libnetmgr_rmnet_ext`,
  `libqcmap_client`, `libqcmap_cm`, and `libqcmapipc`.
- GNSS/location: `libloc_api_v02`, `liblocation_api`,
  `liblocation_client_api`, `liblocation_qapi`, and related location libraries.

The live QRTR registry exposes NAS, DMS, WDS, UIM, WMS, AT, and location
services. The active vendor services include `atfwd`, `quectel_daemon`,
`ql-netd`, `ql-nw-service`, `QCMAP_ConnectionManager`, `loc_launcher`, and
`edgnss-daemon`.

AT bridge access is single-command. Cellular collection, GNSS collection, and
USP operations must serialize access to it.

## Persistent native QMI session

The production collector should maintain native QMI clients instead of opening
a new AT process for every USP parameter. The runtime ABI was verified directly
from the libraries installed on this device:

| USP responsibility | Native QMI service | Installed service object |
|---|---|---|
| Modem identity and functionality | DMS | `dms_get_service_object_internal_v01` |
| Registration, operator, RAT, cells, signal | NAS | `nas_get_service_object_internal_v01` |
| PDP context, addresses and data state | WDS | `wds_get_service_object_internal_v01` |
| SIM identity, slot and PIN state | UIM | `uim_get_service_object_internal_v01` |
| SMS list/send/delete and indications | WMS | `wms_get_service_object_internal_v01` |
| GNSS fixes and session control | Qualcomm location API | installed location client libraries |

`libqmi_cci.so.1` exports the required long-lived client functions, including
`qmi_client_init_instance`, `qmi_client_send_msg_sync`,
`qmi_client_send_msg_async`, `qmi_client_register_error_cb`,
`qmi_client_register_notify_cb`, and `qmi_client_release`. Its transport is the
installed QRTR implementation.

The device does not contain `gcc`, `clang`, or the public DMS/NAS/WDS/UIM/WMS
message headers. Its only public QMI header is the Quectel `ql_net` IPC service
header. Therefore:

- do not build the current `qmi_linux.go` `libqmi-glib` backend for this image;
  QTI `libqmi_cci` is a different ABI;
- do not copy desktop `libqmi-glib` libraries onto the module;
- cross-build the native adapter with the matching QTI
  `LE.UM.5.3.2.r1-06300-SDX65.0` SDK service headers;
- dynamically link the resulting ARMv7 adapter to the libraries already under
  `/usr/lib` on the module;
- keep one client handle for each service and subscribe to indications rather
  than polling every USP path independently.

The session manager must:

1. initialize DMS, NAS, WDS, UIM, and WMS clients once;
2. register service-error and service-notify callbacks;
3. cache a timestamped snapshot, never subscriber secrets in logs;
4. update the snapshot from NAS/WDS/UIM/WMS indications;
5. coalesce concurrent USP `Get` requests onto that snapshot;
6. reconnect only the failed service with bounded exponential backoff and
   jitter;
7. recollect affected values after each USP `Set` or `Operate`;
8. fall back to the serialized AT bridge only while a required QMI service is
   unavailable or for Quectel-only measurements.

The backend must not hold a global lock while waiting for QMI responses. Each
service has its own request serialization and timeout. The snapshot lock only
protects short in-memory copies.

## USP data-model mapping

### `Device.Cellular`

One physical modem is published as one `Device.Cellular.Interface.1` row. The
six `rmnet_data{i}` mux interfaces must not create six modem rows.

| USP parameter | Native source |
|---|---|
| `Interface.{i}.Enable` | modem functionality and active configuration |
| `Interface.{i}.Status` | registration plus active PDP address/route |
| `Interface.{i}.Name` | active default-route rmnet interface |
| `Interface.{i}.IMEI` | DMS or `AT+GSN` |
| `Interface.{i}.CurrentAccessTechnology` | NAS or `AT+QNWINFO`/`AT+QENG` |
| `Interface.{i}.NetworkInUse` | NAS or `AT+COPS?` plus MCC/MNC |
| `Interface.{i}.RSSI/RSRP/RSRQ/SINR` | NAS or Quectel signal commands |
| `Interface.{i}.USIM.*` | UIM or `AT+CIMI`, `AT+ICCID`, and `AT+CPIN?` |
| `Interface.{i}.Stats.*` | `/sys/class/net/<active-rmnet>/statistics/*` |
| `Interface.{i}.SMS.*` | WMS or `AT+CPMS?`/`AT+CMGL` |
| `AccessPoint.{i}.*` | active PDP context (`CGDCONT`/`CGCONTRDP`) |

Verified live state includes home registration on MCC/MNC `604/02`, LTE band
3 as the primary carrier, LTE carrier aggregation, NR NSA band n78 when
available, a ready SIM in slot 1, and an active IPv4 PDP context. RF values and
the active rmnet mux change over time and must be collected live rather than
cached.

ICCID responses on this firmware can end in an `F` padding nibble. The USP
value is the decimal ICCID with the padding removed. Neighbor-cell `QENG` rows
place RSRQ before RSRP. `NR5G BAND 78` maps to `n78`; the `5` in `NR5G` is not
part of the band number.

### `Device.IP.Interface`

Publish rmnet interfaces even though they have no Ethernet MAC address. The
active cellular interface is determined from the default route, not by assuming
`rmnet_data0`; the observed connection moved from `rmnet_data0` to
`rmnet_data1` during live testing.

The active interface currently carries an IPv4 `/30` address and host routes
to the carrier DNS servers. Interface statistics must come from that same
active rmnet row. `Device.IP.Interface` has no `MACAddress` parameter, so the
backend must not invent one there.

### `Device.Firewall`

The live system uses iptables 1.8.4 legacy, not nftables or OpenWrt UCI. USP
firewall collection must read the effective `raw`, `nat`, `mangle`, and
`filter` tables. Current behavior includes:

- masquerading on the active rmnet WAN interface;
- TCP MSS rules between the LAN bridge and cellular WAN;
- WAN drops for TCP ports 80 and 443;
- LAN/Ethernet/tunnel allowances for the local web service;
- forwarding rules between the cellular WAN and `bridge0`.

The firewall backend must map these rules into `Device.Firewall.Chain` and
`Rule` objects without treating this QTI image as an OpenWrt/UCI target.

### GNSS and location

The native location stack is preferred: `loc_launcher`, `edgnss-daemon`, the
location message socket, and the installed Qualcomm location libraries. The
Quectel AT fallback uses `AT+QGPS`, `AT+QGPSLOC`, and NMEA queries.

GNSS is represented through the standard location row where applicable, with
the existing WUSP receiver telemetry used only for values not represented by
the selected TR-181 version. Starting and stopping a GNSS session are USP
`Operate` actions. A stop can return CME error 505 while the native location
service owns an active session; the backend must coordinate with the native
location API instead of forcing the AT session off.

### SMS

SMS read/send/delete remain USP `Operate` actions. The preferred service is QMI
WMS. This image also supplies working AT/CGI flows:

- list: configure text mode/storage and issue `AT+CMGL="ALL"`;
- delete: `AT+CMGD=<index>`;
- send: the installed `send_sms` bridge, which handles the `CMGS` prompt.

Phone numbers and message content are operation inputs and must not appear in
normal telemetry or logs.

## AT fallback command matrix

This table is the diagnostic and fallback contract. Commands are tried in the
listed order for the associated USP value. A command returning `ERROR`, a CME
or CMS error, a timeout, an empty mandatory field, or an out-of-range value
does not overwrite the last valid native-QMI value.

### Identity, SIM, registration, and packet service

| USP path or operation | AT command | Expected response and interpretation |
|---|---|---|
| `Device.Cellular.Interface.{i}.IMEI` | `AT+GSN`, then `AT+CGSN` | Exactly 15 decimal digits |
| telemetry manufacturer | `AT+CGMI` | `Quectel` on this target |
| telemetry model | `AT+CGMM`, then `ATI` | `RM520N-GL`; `ATI` also includes firmware |
| telemetry revision | `AT+CGMR` | Firmware revision string |
| `USIM.IMSI` | `AT+CIMI` | 14 or 15 decimal digits |
| `USIM.ICCID` | `AT+ICCID`, then `AT+CCID` | Decimal ICCID; remove a trailing `F` padding nibble |
| `USIM.MSISDN` | `AT+CNUM` | Parse the quoted telephone number when provisioned |
| `USIM.Status` / `PINCheck` | `AT+CPIN?` | `READY`, `SIM PIN`, or an error state |
| control SIM slot | `AT+QUIMSLOT?` | `+QUIMSLOT: <1..4>` |
| control functionality | `AT+CFUN?` | `1=Full`, `0=Disabled`, `4=LowPower` |
| registration state | `AT+C5GREG?`, `AT+CEREG?`, `AT+CGREG?`, `AT+CREG?` | Prefer the newest registered domain; status `1=Home`, `5=Roaming`, `2=Searching`, `3=Denied` |
| network/operator | `AT+COPS?` | Operator format/name and access-technology code |
| MCC/MNC, RAT, band | `AT+QNWINFO` | Example: `"FDD LTE","60402","LTE BAND 3",1650` |
| PDP definitions/APN | `AT+CGDCONT?` | Context ID, PDP type, APN and configured address |
| live PDP address/DNS | `AT+CGCONTRDP` | Active context, APN, local address, gateway and DNS |
| Quectel WAN state | `AT+QMAP="WWAN"` | Use when `CGCONTRDP` omits router-mode WAN data |
| connect operation | `AT+CGDCONT=<cid>,"<type>","<apn>"`, then `AT+CGACT=1,<cid>` | Validate APN/PDP type before quoting; recollect WDS/PDP state afterward |
| disconnect operation | `AT+CGACT=0,<cid>` | Recollect route and PDP state afterward |

PDP connection truth comes from WDS and the kernel route/address state. An AT
address alone is not sufficient if no active rmnet route exists.

### Signal, serving cell, carriers, and neighbors

| USP path | AT command | Expected response and interpretation |
|---|---|---|
| `RSSI` and legacy quality | `AT+CSQ` | `0..31`; `99` is unknown; convert valid CSQ to dBm |
| RAT-specific signal | `AT+QCSQ` | LTE/NR RSSI, RSRP, SINR and RSRQ |
| standard extended signal | `AT+CESQ` | Fallback when `QCSQ` is unavailable |
| serving cell, CellID, TAC, PCI | `AT+QENG="servingcell"` | Parse LTE and NR5G-SA/NSA rows independently |
| per-chain/aggregate RSRP | `AT+QRSRP` | Average only valid antenna-chain measurements |
| per-chain/aggregate RSRQ | `AT+QRSRQ` | Average only valid antenna-chain measurements |
| per-chain/aggregate SINR | `AT+QSINR` | Apply the firmware-specific encoded-to-dB conversion |
| CA carrier rows | `AT+QCAINFO` | PCC/SCC, EARFCN/NR-ARFCN, bandwidth, band, PCI and RF values |
| LTE neighbors | `AT+QENG="neighbourcell"` | This firmware orders fields as RSRQ then RSRP |
| NR measurements | `AT+QNWCFG="nr5g_meas_info"` | NR frequency, PCI, RSRP and RSRQ when supported |
| modem temperature | `AT+QTEMP` | Publish a valid modem temperature, not unrelated sensor values |
| LTE timing advance | `AT+QNWCFG="lte_time_advance",1;+QNWCFG="lte_time_advance"` | Quectel LTE timing-advance value |
| NR timing advance | `AT+QNWCFG="nr5g_time_advance",1;+QNWCFG="nr5g_time_advance"` | Quectel NR timing-advance value |
| modem data counters | `AT+QGDCNT?;+QGDNRCNT?` | Diagnostic only; USP interface counters prefer active-rmnet sysfs |

When both LTE and NR carriers are present, publish NR mode as NSA even if
`QNWINFO` momentarily reports only LTE. Parse `NR5G BAND 78` as `n78`, not
`n578`.

### SMS

| USP operation/value | AT command | Notes |
|---|---|---|
| storage capacity/used | `AT+CPMS?` | Maps to `SMS.Storage` capacity and availability |
| list messages | `AT+CMGF=1`, select storage with `AT+CPMS`, then `AT+CMGL="ALL"` | Preserve message index for later delete; normalize output for the USP result |
| delete one message | `AT+CMGD=<index>` | Index must be a positive decimal value returned by list |
| delete all messages | `AT+CMGD=,4` | Destructive; expose only through an explicitly authorized USP operation |
| send message | `AT+CMGF=1`, `AT+CMGS="<number>"`, body, Ctrl-Z | Use QMI WMS first; AT fallback must handle the interactive prompt and CMS errors |

On this image the installed `send_sms` bridge already implements the CMGS
prompt and should be used instead of reimplementing terminal prompt handling.

### GNSS

| USP operation/value | AT command | Notes |
|---|---|---|
| current session state | `AT+QGPS?` | `+QGPS: 1` means an active session |
| start | `AT+QGPSCFG="nmeasrc",1`, then `AT+QGPS=1` | Native Qualcomm location API is preferred |
| stop | `AT+QGPSEND` | CME 505 indicates the native location service owns/conflicts with the session |
| fix/location | `AT+QGPSLOC=2` | UTC, latitude, longitude, HDOP, altitude, fix and motion fields |
| GGA | `AT+QGPSGNMEA="GGA"` | Position, fix quality, satellites used, HDOP and altitude |
| RMC | `AT+QGPSGNMEA="RMC"` | Validity, position, speed, course, UTC date/time |
| GSA | `AT+QGPSGNMEA="GSA"` | Fix dimension, satellites used and dilution values |
| GSV | `AT+QGPSGNMEA="GSV"` | Satellites in view and per-satellite observations |

An empty NMEA sentence such as `$GPGGA` is not a valid fix. USP location values
retain the last timestamped valid fix while status becomes `Searching` or
`NoFix`.

### Kernel-only USP values

The following values must not be inferred from AT commands:

| USP path | Stable source |
|---|---|
| `Device.IP.Interface.{i}.*` | netlink/getifaddrs plus `/sys/class/net` |
| `Device.Cellular.Interface.{i}.Stats.*` | active rmnet `/sys/class/net/<name>/statistics` |
| active cellular interface name | IPv4/IPv6 default route and WDS mux binding |
| `Device.Firewall.*` | `iptables-save` on this firmware |
| interface operational status | kernel flags, carrier, addresses, and routes |

## Write and operation semantics

Writes must preserve USP behavior:

- APN and interface configuration parameters use USP `Set`, validate values,
  apply the native change, and report the resulting USP status.
- `StartGNSS`, `StopGNSS`, `RefreshGNSS`, `SendSMS`, `ListSMS`, and `DeleteSMS`
  are USP `Operate` commands.
- Radio reset, SIM switching, and modem functionality changes are explicit
  `Operate` commands because they can interrupt connectivity.
- Every operation must address the single modem row and serialize native modem
  access.
- A successful native command is followed by live recollection so the
  controller sees actual state, not the requested value echoed back.

The QTI host backend also applies standard USP mutations directly:

- USP `Add` on `Device.Firewall.Chain.{i}.Rule.` appends an iptables rule to
  the selected live table/chain and returns the created instance path;
- USP `Set` on supported firewall rule leaves replaces the corresponding live
  rule with `iptables -R`;
- USP `Delete` on a firewall rule removes that live rule by its current chain
  order;
- USP `Set` on `Device.IP.Interface.{i}.Enable` uses `ip link ... up/down`;
- USP `Set` on `Device.IP.Interface.{i}.MaxMTUSize` validates the range and
  applies the MTU through `ip link`.

Because iptables rule numbers and network-interface instance numbers are live
indexes, a controller should recollect immediately before a mutation and again
after success. The backend does not silently translate an unsupported write
into a reported device success.

## Live development

Build and run a one-shot device snapshot:

```sh
make adb-test-run ADB_GOARCH=arm ADB_GOARM=7
```

Continuously rebuild, push, and rerun after relevant source changes:

```sh
make adb-live ADB_GOARCH=arm ADB_GOARM=7
```

The diagnostic emits raw modem data and the corresponding USP fields. A run is
acceptable only when the collected message validates against the registered
data model and exactly one cellular interface row represents the RM520N-GL.

## Live validation record

The completed live validation confirmed:

- exactly one `Device.Cellular.Interface` row for the RM520N-GL;
- the row followed the active default route to `rmnet_data1` and reported
  `Status=Up`;
- modem/SIM identity, registration, APN, IPv4, carrier DNS, signal, serving
  cell, CA, neighbors, temperature, SMS storage, and interface counters were
  populated from live values;
- `ListSMS` returned structured JSON through the USP operation path without
  deleting or modifying stored messages;
- four live iptables chains and their effective rules were projected into
  `Device.Firewall` (224 firewall fields in that snapshot);
- GNSS start/state/stop were exercised, and the final modem state was verified
  as `+QGPS: 0`;
- the complete selected USP message passed strict schema validation with no
  validation errors.
