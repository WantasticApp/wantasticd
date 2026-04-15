# WUSP Controller Integration Guide

This directory contains Wantastic USP:

- data-model catalogs for device paths and parameter names
- the canonical `Device` runtime model with stable uint64 path codes
- the binary WUSP message codec
- the custom Wantastic USP transport used over the encrypted WireGuard tunnel

This document is the controller-facing guide for integrating with the current
agent implementation.

## Scope

WUSP does not implement the standard TR-369 message transfer protocols such as:

- MQTT
- WebSocket
- STOMP
- CoAP

Instead, Wantastic carries USP-style operations inside the existing Wantastic
WireGuard/Noise tunnel:

- `Message Type 8` is reserved for WUSP control traffic
- control requests and responses are binary datagrams
- large control payloads are fragmented inside WUSP before being sent
- `Upload` and `Download` use a dedicated in-tunnel stream packet format

The BBF/TR data model files in this package are still used for path names,
parameter metadata, access control, and supported model discovery.

## Canonical Device Model

The controller should treat the agent model as one canonical root:

- root: `device.`
- runtime loader: `RuntimeDevice()`
- code function: `EncodePathCode(path string) uint64`

Path codes are:

- stable `uint64`
- computed as `FNV-1a 64` over the lower-cased canonical path
- canonicalized before hashing, so concrete instance paths such as
  `Device.WiFi.SSID.1.Enable` resolve to the same code as
  `Device.WiFi.SSID.{i}.Enable`

That gives the controller and agent a shared fast selector space without
putting full strings on the wire for common operations.

## Transport Stack

The controller should think about the transport in three layers:

1. Outer transport
   The existing Wantastic encrypted WireGuard transport.

2. Control plane
   `USPAgentRequest` and `USPAgentResponse` frames sent on `Message Type 8`.

3. Bulk transfer plane
   `USPTransferStreamFrame` packets for `Upload` and `Download`, also sent on
   `Message Type 8`.

The current agent only accepts controller traffic from the peer whose public key
matches the configured Wantastic `Server.PublicKey`. In practice, the
controller must be the configured server peer.

### Request ID Management

The controller is responsible for generating unique, non-zero `uint64` request
IDs. The agent echoes the same ID in the response, allowing the controller to
correlate responses with pending requests.

- IDs must be non-zero
- IDs must be unique across all pending requests
- A monotonic counter or high-resolution timestamp is sufficient
- The agent does not validate ID uniqueness; collisions are the controller's
  responsibility

## Supported USP Methods

Method IDs on the wire:

| ID | Method |
| --- | --- |
| 1 | `Get` |
| 2 | `Set` |
| 3 | `Add` |
| 4 | `Delete` |
| 5 | `GetInstances` |
| 6 | `Operate` |
| 7 | `Notify` |
| 8 | `GetSupportedDM` |
| 9 | `GetSupportedProtocol` |
| 10 | `Upload` |
| 11 | `Download` |

## Control Datagram Format

Unfragmented control datagrams contain either:

- `USPAgentRequest`
- `USPAgentResponse`

The common fixed header is:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | version, currently `1` |
| 1 | 1 | kind: `1=request`, `2=response` |
| 2 | 1 | method ID |
| 3 | 1 | flags |
| 4 | 8 | request/response ID, little-endian |

Total fixed header size: **12 bytes**.

### Request Flags

`USPAgentRequest.Flags` bits:

| Bit | Meaning |
| --- | --- |
| 0 | nested WUSP `Message` is present |
| 1 | `Transfer` block is present |
| 2 | `ObjectPath` is present |
| 3 | `Metadata` map is present |
| 4 | `PathCodes` list is present |
| 5 | `ObjectCode` is present |

Request body order after the header:

1. `Paths` string list (always present, may be empty)
2. optional `ObjectPath`
3. optional coded `PathSelectors`
4. optional coded `ObjectSelector`
5. optional nested `Message` blob
6. optional `Transfer` block
7. optional `Metadata` map

### Fast Selector Rules

The controller may send selectors either as strings or as stable uint64 path
codes.

- `Paths` is the compatibility shape
- `PathCodes` is the fast-path shape
- `ObjectPath` is the compatibility shape
- `ObjectCode` is the fast-path shape

The current encoder auto-compacts known string selectors into codes before send.
The decoder resolves coded selectors back into concrete paths after receive.
This means the rest of the agent runtime still works with paths, while the
tunnel gets the smaller coded form.

For paths that are not part of the runtime model, the transport falls back to
strings automatically.

Fast selector shape:

- `Code`: stable uint64 schema path code
- `Instances`: uvarint list aligned with each `{i}` token in the canonical path
- instance value `0` means that token remains unresolved as `{i}`
- instance value `N>0` means the token resolves to concrete ordinal `N`

Examples:

- `Device.WireGuard.Peer.{i}.` -> `Code(peer-object)`, `Instances=[]`
- `Device.WireGuard.Peer.1.` -> `Code(peer-object)`, `Instances=[1]`
- `Device.Mesh.Node.4.Interface.{i}.` -> `Code(...)`, `Instances=[4,0]`

### Response Flags

`USPAgentResponse.Flags` bits:

| Bit | Meaning |
| --- | --- |
| 0 | nested WUSP `Message` is present |
| 1 | `Transfer` result is present |
| 2 | `Paths` list is present |
| 3 | `ObjectPath` is present |
| 4 | `Metadata` map is present |
| 5 | `SupportedDataModel` block is present |
| 6 | `Protocol` block is present |
| 7 | selector-code block is present |

Response body order after the header:

1. `Error` string (always present, empty when no error)
2. optional `Paths` string list
3. optional `ObjectPath`
4. optional nested `Message` blob
5. optional `Transfer` result
6. optional `Metadata`
7. optional selector-code block:
   coded `PathSelectors`, then coded `ObjectSelector`
8. optional `SupportedDataModel`
9. optional `Protocol`

### String, Bytes, Lists, Metadata

The control transport uses unsigned varint lengths.

- string: `uvarint length` + raw bytes
- blob: `uvarint length` + raw bytes
- string list: `uvarint count` + repeated string
- metadata: `uvarint count` + repeated `key string` + `value string`

Metadata keys are sorted during encode when the map has more than one entry.

### Uint64 Path Selector Encoding

`PathSelectors` is encoded as:

- `uvarint count`
- repeated:
  - `uvarint code`
  - `uvarint instance_count`
  - repeated `uvarint instance_value`

`ObjectSelector` is encoded as:

- `uvarint code`
- `uvarint instance_count`
- repeated `uvarint instance_value`

The response selector-code block encodes:

1. coded `PathSelectors`
2. coded `ObjectSelector`

### Nested `Message`

The nested `Message` payload is the binary WUSP message format produced by:

- `EncodeMessage`
- `DecodeMessage`

The controller should reuse this package or implement the same codec if it is
not written in Go.

Nested messages are compressed automatically when beneficial:

- always when the nested message has at least 8 fields
- also when the estimated nested payload grows beyond about 512 bytes

## Per-Method Request Rules

The current wire validator enforces these minimum rules:

- `Get`: at least one `Path` or `PathCode` is required; `Paths` may be empty
  when `PathCodes` are provided instead
- `Set`: `Message` is required and must contain at least one field
- `Add`: `ObjectPath` or `ObjectCode` is required
- `Delete`: at least one `Path` or `PathCode` is required
- `GetInstances`: at least one `Path` or `PathCode` is required; object paths
  should end with `.`
- `Operate`: `ObjectPath` or `ObjectCode` is required
- `Notify`: `ObjectPath` or `ObjectCode` is required
- `GetSupportedDM`: optional path filters may be sent in `Paths`
- `GetSupportedProtocol`: no extra fields required
- `Upload`: `Transfer` block is required
- `Download`: `Transfer` block is required

Object paths must end with `.`.

When calling `HandleRequest` in-process (without wire encoding), `Get` with
no paths or codes returns the full stored state snapshot.

## Control Fragmentation

Control datagrams larger than the current datagram budget are fragmented before
send. The current maximum target payload is:

- `WUSPMaxDatagramPayload = 1200`

Fragment frames are identified by:

- magic byte `0x54`
- version `1`

Fragment header:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | magic `0x54` |
| 1 | 1 | version `1` |
| 2 | 1 | flags |
| 3 | 8 | `MessageID`, little-endian |
| 11 | 4 | `Index`, little-endian |
| 15 | 4 | `Count`, little-endian |
| 19 | 4 | `RawSize`, little-endian |
| 23 | n | fragment data |

Fragment flags:

- bit `0`: compressed

Fragment behavior:

- compression is applied to the whole control payload before splitting
- compression is attempted only when the raw control payload is at least 512 bytes
- fragments must all share the same `MessageID`
- reassembly requires a complete `0..Count-1` set
- if `Compressed=true`, `RawSize` must be non-zero and the reassembled payload
  is LZ4-decompressed before request/response decode

Controller receive path for `Message Type 8` should be:

1. try `DecodeUSPControlFragment`
2. if fragment, buffer by `MessageID` until all fragments are present
3. reassemble
4. decode the resulting control payload as request/response, or as a stream
   frame if it is actually transfer traffic

## Recommended Controller Fast Path

For controller performance, the best flow is:

1. load the same runtime model or generate the same path-code table
2. use `PathCodes` / `ObjectCode` for `Get`, `Delete`, `Add`,
   `GetInstances`, `Operate`, and `Notify`
3. use batch `Get` by sending multiple `PathCodes`
4. use batch `Set` by sending one nested `Message` with multiple fields
5. let the nested `Message` codec keep using the existing field registry IDs

This keeps the control envelope compact without inventing a second field-value
codec for set payloads.

## Upload and Download Stream Format

`Upload` and `Download` bulk data do not use the normal control datagram
format. They use `USPTransferStreamFrame`.

Stream frame identification:

- magic byte `0x53`
- version `1`

Phases:

| Value | Phase |
| --- | --- |
| 1 | `Open` |
| 2 | `Chunk` |
| 3 | `Ack` |
| 4 | `Complete` |
| 5 | `Abort` |

Fixed header layout:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | magic `0x53` |
| 1 | 1 | version `1` |
| 2 | 1 | phase |
| 3 | 1 | method, must be `Upload` or `Download` |
| 4 | 1 | flags |
| 5 | 8 | `SessionID`, little-endian |
| 13 | 8 | `RequestID`, little-endian |
| 21 | 4 | `Sequence`, little-endian |
| 25 | 4 | `AckSequence`, little-endian |
| 29 | 8 | `Offset`, little-endian |
| 37 | 8 | `TotalSize`, little-endian |
| 45 | n | optional variable fields |

Stream flags:

| Bit | Meaning |
| --- | --- |
| 0 | `Final` |
| 1 | `Path` is present |
| 2 | `Filename` is present |
| 3 | `ContentType` is present |
| 4 | `Metadata` is present |
| 5 | `Data` is compressed |
| 6 | `Data` is present |

Optional fields are encoded in this order:

1. optional `Path`
2. optional `Filename`
3. optional `ContentType`
4. optional `Metadata`
5. optional `Data`

If `Data` is compressed, the payload writes:

1. raw uncompressed size as uvarint
2. compressed blob

Current transfer compression behavior:

- chunk compression is only attempted for chunks at least 256 bytes
- obvious high-entropy payloads are skipped
- LZ4 is only kept if the compressed bytes are smaller than the original

## Current Transfer Session Behavior

The current agent implementation advertises:

- `RecommendedChunkSize = 1120`
- transfer window size `8`
- ACK timeout `2s`

### Upload to Agent

Controller flow:

1. send control request `Method=Upload` with a `Transfer` block
2. wait for control response
3. read `Transfer.Metadata["session_id"]`
4. send stream `Open`
5. wait for stream `Ack` with `AckSequence=0`
6. send ordered `Chunk` frames starting at sequence `1`
7. mark the last chunk with `Final=true`
8. send stream `Complete`
9. wait for stream `Complete` response from the agent

Agent upload behavior today:

- upload chunks must arrive strictly in sequence
- ACKs are cumulative
- the agent writes to a buffered file writer
- on `Abort`, the partial target file is removed

### Download from Agent

Controller flow:

1. send control request `Method=Download` with a `Transfer` block
2. wait for control response
3. read `Transfer.Metadata["session_id"]` and `chunk_size`
4. receive stream `Open`
5. receive stream `Chunk` frames
6. send `Ack` frames carrying the highest contiguous `AckSequence`
7. receive stream `Complete`

Agent download behavior today:

- chunks are sent with a sliding window of 8
- ACKs are cumulative
- on ACK timeout, all pending chunks are resent
- the agent does not currently wait for a final ACK on the `Complete` frame

## Transfer Request Fields

The `Transfer` block on the control request is:

- `Path`
- `URI`
- `Filename`
- `ContentType`
- `Payload`
- `Metadata`

Current tunnel-transfer usage on the agent side:

- `Upload`
  - destination is resolved from `file://` URI, then `Metadata["destination"]`,
    then `Filename`
- `Download`
  - source is resolved from `file://` URI, then `Metadata["source"]`,
    then `Filename`

For in-tunnel transfers, the controller should prefer:

- `file://...` URIs for explicit local file paths on the agent
- `Metadata["size"]` for uploads when the total length is known
- `ContentType` when known

`Transfer.Payload` exists in the control schema but should be treated as small
metadata-scale content, not as the main bulk-transfer path.

## Supported Protocol Discovery

`GetSupportedProtocol` currently returns:

- `Name = "wantastic-wusp-over-wireguard"`
- `Version = 1`
- `Methods = [Get, Set, Add, Delete, GetInstances, Operate, Notify, GetSupportedDM, GetSupportedProtocol, Upload, Download]`
- `Compression = [nested-message-lz4, stream-chunk-lz4]`
- `ControlTransport = "wireguard-noise-fragmented-datagram"`
- `TransferTransport = "wireguard-noise-stream-packets"`
- `MaxControlPayload = 1200`
- `RecommendedChunkSize = 1120`
- `TunnelOnly = true`
- `ReliableTransfer = true`

Controllers should call `GetSupportedProtocol` first and adapt to what the
agent actually reports rather than hard-coding assumptions.

## Supported Data Model Discovery

Use `GetSupportedDM` to discover:

- bundled model catalogs
- supported object paths
- supported parameter paths
- access mode and parameter type

This is the preferred way for the controller to learn the agent's current path
surface instead of assuming every BBF model file in this folder is writable or
implemented by the active platform backend.

## WUSP Data Model Parameters

The agent exposes its own transport configuration under `Device.WUSP.*`.
These are readable via a normal `Get` request and do not require
`GetSupportedProtocol`.

Key parameters:

| Path | Access | Type | Description |
| --- | --- | --- | --- |
| `Device.WUSP.Enable` | ReadWrite | bool | Enable/disable the WUSP transport |
| `Device.WUSP.Status` | ReadOnly | string | `Dormant`, `Active`, or `Error` |
| `Device.WUSP.ProtocolVersion` | ReadOnly | string | WUSP framing version |
| `Device.WUSP.ControllerEndpointID` | ReadWrite | string | Expected controller endpoint ID |
| `Device.WUSP.ControllerPublicKey` | ReadWrite | string | WireGuard public key of the authorized controller |
| `Device.WUSP.MaxControlPayload` | ReadOnly | uint | Maximum unfragmented control payload in bytes |
| `Device.WUSP.RecommendedChunkSize` | ReadOnly | uint | Recommended stream chunk size in bytes |
| `Device.WUSP.TransferWindowSize` | ReadOnly | uint | Recommended max in-flight transfer chunks |
| `Device.WUSP.TunnelOnly` | ReadOnly | bool | Always `true` for this transport |
| `Device.WUSP.ReliableControl` | ReadOnly | bool | Whether control has explicit reliability |

Multi-instance tables under `Device.WUSP.*`:

- `Device.WUSP.Request.{i}.` — in-tunnel operation request rows
- `Device.WUSP.Subscription.{i}.` — notification subscription rows
- `Device.WUSP.Certificate.{i}.` — controller trust certificates
- `Device.WUSP.ControllerTrust.Role.{i}.` — named trust roles

## Error Handling

### Response-level errors

A successful transport exchange always returns a `USPAgentResponse` with `Error`
set to the empty string. Any agent-side failure sets `resp.Error` to a
human-readable message; the rest of the response fields are empty.

The Go error returned by `HandleRequest` is always `nil` for recognized methods
(the agent converts all method-level errors into `resp.Error`). A non-nil Go
error from `HandleRequest` means the method ID itself was unrecognized.

### Sentinel errors

| Symbol | Meaning |
| --- | --- |
| `ErrUSPPathUnsupported` | Path is not implemented by the `DataSetter`; the agent still stores the value in-memory |
| `ErrUSPPathNotFound` | Requested path is absent from the agent's in-memory store |
| `ErrUSPTransferUnsupported` | Upload or Download requested but no handler was configured |
| `ErrUSPTransportMalformed` | Wire payload cannot be decoded |
| `ErrUSPTransportUnsupported` | Unsupported transport version or method ID |
| `ErrUSPTransportMethodRequired` | Request carries method ID `0` |

### ValidationError

`EncodeUSPAgentRequest`, `EncodeUSPAgentResponse`, and their decode counterparts
return a `*ValidationError` when a structural constraint is violated:

```go
type ValidationError struct {
    Path   string // set when the error is path-specific
    Reason string // human-readable constraint violation
}
```

Common causes:

- request ID is `0`
- `Paths` contains an empty string
- `PathInstances` length does not match `PathCodes` length
- `PathCodes` contains a zero code
- `ObjectPath` does not end with `.`
- method-specific required fields are absent (e.g., `Set` with no fields)

## Recommended Controller Receive Loop

For every decrypted `Message Type 8` payload:

1. try fragment decode
2. if fragment, reassemble and restart decode on the reassembled bytes
3. try stream decode
4. if stream, route to transfer session logic
5. try response decode
6. if response, match by request ID
7. try request decode
8. if request, execute it if your controller supports agent-originated requests

The current agent tolerates all-zero tail padding on decoded control frames, so
controllers should do the same if they want symmetric behavior.

## Go Integration

### Agent setup

```go
agent := wusp.NewUSPAgent(wusp.USPAgentOptions{
    // FillProfile seeds Bootstrap with realistic or max-compressible defaults.
    // FillProfileRealistic (default) produces plausible device values.
    // FillProfileMaxCompressible produces highly repetitive values for testing.
    FillProfile: wusp.FillProfileRealistic,

    // Collector queries live device values (e.g., network stats) on Get.
    // Paths the collector does not support are filled from the in-memory store.
    Collector: myPlatformBackend,

    // Setter persists parameter changes to the device (e.g., config files).
    // Paths the setter does not support return ErrUSPPathUnsupported;
    // the agent stores the value in-memory regardless.
    Setter: myPlatformBackend,

    // OperateHandler is called for Operate requests.
    OperateHandler: func(ctx context.Context, cmdPath string, input *wusp.Message, meta map[string]string) (*wusp.Message, error) {
        // execute the command, return output message or error
        return nil, nil
    },

    // NotifyHandler is called for agent-originated Notify requests.
    NotifyHandler: func(ctx context.Context, eventPath string, payload *wusp.Message, meta map[string]string) error {
        return nil
    },

    // UploadHandler and DownloadHandler delegate bulk file transfers.
    UploadHandler:   myUploadFunc,
    DownloadHandler: myDownloadFunc,
})

// Bootstrap seeds all known schema parameters with schema-derived defaults.
// Call this once after construction, before serving requests.
if err := agent.Bootstrap(wusp.FillOptions{
    Profile:  wusp.FillProfileRealistic,
    DeviceID: "usp:device:mydevice:001",
}); err != nil {
    log.Fatal(err)
}
```

### In-process usage

When the controller and agent run in the same Go process, call `HandleRequest`
directly without encoding or fragmenting:

```go
resp, err := agent.HandleRequest(ctx, wusp.USPAgentRequest{
    ID:     nextRequestID(), // non-zero uint64
    Method: wusp.USPAgentMethodGet,
    Paths:  []string{"Device.DeviceInfo.Manufacturer"},
})
if err != nil {
    // unrecognized method
}
if resp.Error != "" {
    // agent-level error
}
for _, field := range resp.Message.Fields {
    fmt.Printf("%s = %v\n", field.Path, field.Val)
}
```

### Wire path (controller sending over WireGuard)

If the controller is implemented inside this repository or another Go module,
reuse these helpers directly:

- `EncodeUSPAgentRequest`
- `DecodeUSPAgentRequest`
- `EncodeUSPAgentResponse`
- `DecodeUSPAgentResponse`
- `FragmentUSPControlPayload`
- `DecodeUSPControlFragment`
- `ReassembleUSPControlFragments`
- `EncodeUSPTransferStreamFrame`
- `DecodeUSPTransferStreamFrame`

That keeps the controller and agent in lockstep on binary format changes.

Minimal controller send example:

```go
encoded, err := wusp.EncodeUSPAgentRequest(req)
if err != nil {
    return err
}
msgID := req.ID // same ID used in fragments for reassembly
fragments, err := wusp.FragmentUSPControlPayload(encoded, msgID, wusp.WUSPMaxDatagramPayload)
if err != nil {
    return err
}
for _, frag := range fragments {
    sendOnWireGuardType8(frag)
}
```

Minimal controller receive example:

```go
var pending map[uint64][]wusp.USPControlFragment

func onWireGuardType8(data []byte) {
    frag, isControlFrag, err := wusp.DecodeUSPControlFragment(data)
    if err != nil {
        return
    }
    if isControlFrag {
        pending[frag.MessageID] = append(pending[frag.MessageID], frag)
        if uint32(len(pending[frag.MessageID])) < frag.Count {
            return // wait for remaining fragments
        }
        data, err = wusp.ReassembleUSPControlFragments(pending[frag.MessageID])
        delete(pending, frag.MessageID)
        if err != nil {
            return
        }
    }
    // try response
    resp, err := wusp.DecodeUSPAgentResponse(data)
    if err == nil {
        dispatchResponse(resp)
        return
    }
    // try stream frame
    frame, err := wusp.DecodeUSPTransferStreamFrame(data)
    if err == nil {
        dispatchStreamFrame(frame)
        return
    }
}
```

## Current Limits

Be aware of the current implementation limits:

- control requests are request/response datagrams with fragmentation, but there
  is not yet a separate WUSP-level ACK/retry layer for fragmented control
  messages
- transfer streams have explicit ACK/retry logic, but control datagrams do not
- upload and download stream logic is implemented on the agent side first; the
  controller must mirror the same session handling
- the active platform backend decides which TR-style paths are actually
  collected or writable

## Controller Checklist

- make the controller peer the configured Wantastic server peer
- send all USP control traffic on Wantastic `Message Type 8`
- generate unique non-zero `uint64` request IDs; correlate responses by ID
- fragment control payloads above the datagram budget
- use `GetSupportedProtocol` and `GetSupportedDM` during capability discovery
- treat `Add`, `Operate`, and `Notify` object paths as object paths ending in `.`
- use cumulative ACKs for streamed download/upload sessions
- prefer `file://` transfer URIs for fully in-tunnel local file exchange
- do not use MQTT/WebSocket/STOMP assumptions for this transport
- check `resp.Error` on every response before reading response fields
