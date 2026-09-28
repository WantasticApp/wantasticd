# EasyMesh through the vendor `device` ubus API

The SPF 12.2 device service is the authoritative abstraction for mesh state.
Wantastic does not infer EasyMesh from files or processes, read `ezmesh` UCI,
link to Qualcomm libraries, write daemon FIFOs, or reload the EasyMesh service.

## Read-only integration

- `device.getMode` identifies whether the local device is the CN central node.
- `device.getRealTopo` returns the controller topology.
- The EasyMesh-specific WUSP row is emitted only when the local mode is CN.
- Agent and relay devices may still report generic mesh telemetry, but they do
  not expose the EasyMesh console tab.

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

The integration is intentionally read-only until the payload meaning and
success/error responses of `device.setTopo`, `device.setMode`, and
`device.rmStation` are verified on the target firmware. Their ubus signatures
alone are not enough to invent safe controller actions.
