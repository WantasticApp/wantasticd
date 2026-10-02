# EasyMesh through the vendor `device` ubus API

The SPF 12.2 device service is the authoritative abstraction for mesh state.
Wantastic does not infer EasyMesh from files or processes, link to Qualcomm
libraries, write daemon FIFOs, or reload the EasyMesh service. Topology writes
also use the daemon's loopback-only command console to enable its otherwise
disabled backhaul-request gate for the duration of the vendor call.

## Telemetry integration

- `device.getMode` identifies whether the local device is the CN central node.
- `device.getRealTopo` returns the live controller topology.
- `device.getTopo` returns the exact editable topology policy currently used by
  the controller. The agent validates this response before advertising writes.
- The EasyMesh-specific WUSP row is emitted for confirmed CN and RN roles.
- CN rows expose validated topology policy control. RN rows expose the
  `rmStation` and controller-promotion contracts verified in this vendor RPC
  service; the RPC call itself remains authoritative if firmware rejects one.

The known topology response is:

```json
{
  "topo": [
    {
      "mac": "00:03:7F:BA:DB:AD",
      "pMac": "",
      "hops": 0,
      "ip": "192.168.200.1",
      "backhaul": "B",
      "name": ""
    }
  ]
}
```

The parser also supports multiple flat records. `pMac` supplies the parent,
`hops` supplies the controller-relative depth, `B` represents the root, and
`H`/`L` represent wireless backhaul bands.

## CN safety gate

String modes `CN`, `central`, `controller`, `root`, and `CAP` are treated as
central. Known agent modes such as `RE`, `agent`, `relay`, `extender`, and
`satellite` are rejected. Unknown numeric modes are not guessed. When the mode
response is unavailable or unknown, the fallback requires the topology's
zero-hop parentless node to match a local interface MAC, IP address, or hostname.

## Verified topology control

The target firmware's `/usr/lib/rpcd/uai.so` contract has been verified. The
`device.setTopo` method accepts one string parameter named `data`. The string
is a JSON document that the firmware validates, stores at
`/etc/topo-ezmesh.json`, and passes to `ezcmd td topt`.

```json
{
  "topOptPolicy": "strict",
  "convTimeout": 60,
  "deviceArray": [
    {
      "alId": "00:03:7F:BA:DB:AD",
      "parentAlId": "NULL",
      "bStaLinkBand": "6GHL",
      "depth": 0,
      "rssiThresh": -70,
      "apName": "Controller"
    }
  ]
}
```

Wantastic exposes `ApplyTopology()` only when the device is the confirmed CN
and `getTopo` (or the on-device policy file fallback) returns a valid policy
whose node inventory exactly matches `getRealTopo`. That document is the base
for every UI edit. A missing, malformed, or stale policy keeps the EasyMesh row
visible for diagnostics but omits `ApplyTopology` and `TopologyJSON`. The
controller must first publish a consistent vendor policy before cloud topology
editing is enabled.

The vendor controller accepts only `strict` and `permissive` for
`topOptPolicy`. `strict` keeps the requested parent graph authoritative;
`permissive` allows the controller to choose another viable path. Wantastic
migrates the invalid `manual` value emitted by early console builds to
`strict` before applying the policy.

SPF 12.2 keeps a separate process-local `g_TopOptRequestSendFlag` disabled by
default. Without enabling it, `td topt` accepts and prints the requested graph
but reports `Do not Send TopOpt Request!!`. Wantastic connects only to
`127.0.0.1:7777`, sends the fixed command `td test on`, calls
`device.setTopo`, and restores the gate with the fixed command `td test off`
after that RPC returns. The extracted `uai.so` invokes `ezcmd td topt`
synchronously, and `libtdService.so` checks the flag while that command emits
each vendor steering request. The `time1`/`time2` values printed by the command
are carried as request timeouts; they do not require the send gate to remain
open during the whole convergence interval. No arbitrary console command is
accepted from WUSP input.

The USP operation is acknowledged as `Pending` and completed asynchronously
because the controller can schedule per-node steering after the RPC returns.
The agent publishes `Accepted`, `Applying`, `Converging`, and terminal
`Complete`/`Failed` phases immediately through WUSP `DataModelChange!`
notifications. The portal consumes those pushes and does not run a second
polling loop. While convergence is active, each changed `getRealTopo` parent
graph is also converted to WUSP node/link rows and pushed immediately;
unchanged samples are suppressed by a stable graph fingerprint. The vendor RPC
has its own fixed 30-second safety deadline; the
user-facing cloud request never waits for either that deadline or radio
convergence. The `convTimeout` field applies only to live parent-graph
convergence after the saved policy has been confirmed.
The synchronous `device.getTopo` read-back must exactly match the requested
document before Wantastic waits for live convergence. This prevents a staged
timeout or graph from being presented as saved when the device retained a
different value. Success is published only after both the saved policy and
`device.getRealTopo` match the requested graph continuously for the stability
window. A brief match followed by a rollback remains pending and then reports
an exact convergence failure. Failure to enable or restore the daemon gate is
reported as an operation error.

Before calling ubus, the agent limits the payload to 64 KiB and 128 nodes,
rejects unknown JSON fields, validates all MAC addresses and radio-band enums,
requires exactly one root, and rejects missing parents, inconsistent depths,
self-parenting, cycles, control characters, and out-of-range timeout/RSSI
values. The ubus call uses a structured parameter map rather than shell text.

## SPF 12.2 firmware evidence

The extracted `qca-ezmesh_gdc773b1-1` and `qca-ezmesh-cmn_gdc773b1-1`
packages provide two different topology mechanisms. They must not be treated as
interchangeable:

- `/usr/sbin/ezmesh-cmd topopt` writes the fixed `topopt` command to
  `/var/run/ezmesh-ctrl-cmd.fifo`. The vendor init script installs that same
  command as the periodic `EnableTopologyOpt` cron job. Its handler is
  `mapCtrlAlgTopologyOptHandler`, which starts the controller's automatic
  capacity-based optimizer; it does not accept a requested parent graph.
- `libmapServiceCtrl.so` exports
  `mapServiceCtrlSendBackhaulSteeringRequest`. Its request contains a BSTA MAC,
  target BSSID, operating class, and channel. Calling this library from a new
  process is not valid because the library expects the EasyMesh controller's
  in-process topology, message buffers, event loop, and IEEE 1905 state.
- The saved `device.setTopo` graph is handled by `libtdService.so`. Its sender
  checks `g_TopOptRequestSendFlag` before emitting each request. This is why a
  graph can be saved while no live parent changes: the observed trace printed
  `Do not Send TopOpt Request!!` for both requested relay changes.

Wantastic therefore does not use the automatic `ezmesh-cmd topopt` FIFO as a
substitute for an operator-selected graph and does not load the native shared
objects into its own process. The existing typed `device.setTopo` request plus
bounded local gate and authoritative read-back is the only recovered path that
preserves the requested parent relationships on this firmware.

## SkyNet Bigo reference agent

The extracted SkyNet Bigo agent is a useful reference for reporting behavior,
but it is not evidence of a second topology-write API. The analyzed artifact
was `bigo_agent.xz` from the extracted AI_QCA_0004 firmware:

- compressed SHA-256:
  `f0ea5f527ac562199e1f7ea155a96574229b2a4124882d6e0ff4fbdd51a3fcad`;
- decompressed SHA-256:
  `bc100e39454918ace42be5634386e07d841e8fb8697f0de8e946384be2ad677f`;
- static ARM64 Go 1.20.14 binary, built with the `SC7161,CN` tags;
- module `agent`, revision `ed9d0c462a9b7aa424dc69ebe12dcc037ef40a85`.

Recovered Go function metadata and disassembly show that its topology reporter
runs every 60 seconds, skips non-root APs, calls `device.getRealTopo`, and
publishes the resulting `TopologyInfos` asynchronously. Its cloud command
registry contains `setMode` and `rmStation`, but no `setTopo` handler. Wantastic
therefore adopts the confirmed root gate and asynchronous reporting pattern;
manual graph mutation continues to use the separately verified `uai.so`
`device.setTopo` contract.

## Recovery lesson and mutation boundary

A saved policy is not proof that radios moved. `device.getTopo` proves only the
persisted controller plan; `device.getRealTopo` is the live result. On the test
firmware a requested chain was stored while both relays remained attached to
the CN, so the operation must stay in `Converging` and eventually report the
precise failure instead of claiming success.

Topology control must never write wireless UCI channel or HT-mode settings,
invoke `wifi reload`, or restart EasyMesh. During device investigation,
changing `wifi2`/`wifi3` from the vendor's `EHT0` state caused the `ath2`,
`ath21`, `ath3`, and `ath31` hotplug retry loop. Explicit `EHT320` restored
hostapd generation on that image, but this is a firmware recovery detail, not
part of topology apply. Wantastic's mutation boundary remains the console gate
and structured `device.setTopo` call only.

## Verified RN control contracts

The same SPF 12.2 `/usr/lib/rpcd/uai.so` binary defines these policies:

- `device.rmStation` accepts string parameters `station` and `user`. The first
  selects the hostapd station/interface and the second is the client MAC. The
  agent validates both before making the structured ubus call.
- `device.setMode` accepts one integer parameter named `mode`. This firmware
  accepts only `1`, which promotes the device to root/controller and changes
  its boot environment. It does not expose a symmetric demotion or handover.

The console therefore blocks controller promotion while another controller is
visible. This single-controller invariant is also enforced by the agent, so a
forged browser request cannot create two CNs. SPF 12.2 exposes no
`device.addStation` method; new clients join using valid mesh Wi-Fi credentials
and the console must not simulate an unsupported RPC.
