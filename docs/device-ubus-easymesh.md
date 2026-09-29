# EasyMesh through the vendor `device` ubus API

The SPF 12.2 device service is the authoritative abstraction for mesh state.
Wantastic does not infer EasyMesh from files or processes, read `ezmesh` UCI,
link to Qualcomm libraries, write daemon FIFOs, or reload the EasyMesh service.

## Telemetry integration

- `device.getMode` identifies whether the local device is the CN central node.
- `device.getRealTopo` returns the controller topology.
- The EasyMesh-specific WUSP row is emitted for confirmed CN and RN roles.
- CN rows expose validated topology policy control. RN rows expose only the
  capabilities proven by the local `device` ubus method list.

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
`/etc/topo-ezmesh.json`, and applies through its EasyMesh controller.

```json
{
  "topOptPolicy": "manual",
  "convTimeout": 120,
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

Wantastic exposes `ApplyTopology()` only when the device is the CN and either
the ubus method list contains `setTopo` or the current topology policy file is
present and passes strict validation. The existing validated document is the
base for every UI edit; the console does not invent missing policies or links.

Before calling ubus, the agent limits the payload to 64 KiB and 128 nodes,
rejects unknown JSON fields, validates all MAC addresses and radio-band enums,
requires exactly one root, and rejects missing parents, inconsistent depths,
self-parenting, cycles, control characters, and out-of-range timeout/RSSI
values. The ubus call uses a structured parameter map rather than shell text.

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
