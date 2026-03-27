package grpc

// Hand-crafted protobuf wire encoding for export-related RPC methods.
//
//   ValidateExportToken
//   ───────────────────
//   Request  field 1: token (string)
//   Response field 1: valid (bool, varint)
//
//   RegisterPeer
//   ────────────
//   Request  field 1: account_id (string)
//            field 2: public_key (string, hex-encoded)
//   Response field 1: assigned_ip      (string)
//            field 2: server_ip        (string)
//            field 3: server_port      (int32, varint)
//            field 4: server_public_key (string)

import "google.golang.org/protobuf/encoding/protowire"

// ExportPeerInfo holds the result of a successful RegisterPeer call.
type ExportPeerInfo struct {
	AssignedIP   string // IP address assigned to this device in the target network
	ServerIP     string // Target server's IP address
	ServerPort   int    // Target server's WireGuard listen port
	ServerPubKey string // Target server's WireGuard public key (base64 or hex)
}

// ── ValidateExportToken ────────────────────────────────────────────────────

func marshalValidateExportTokenRequest(token string) []byte {
	var b []byte
	if token != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, token)
	}
	return b
}

func unmarshalValidateExportTokenResponse(data []byte) bool {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return false
			}
			return v != 0
		default:
			n = protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return false
			}
			data = data[n:]
		}
	}
	return false
}

// ── RegisterPeer ───────────────────────────────────────────────────────────

func marshalRegisterPeerRequest(accountID, pubKeyHex string) []byte {
	var b []byte
	if accountID != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, accountID)
	}
	if pubKeyHex != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, pubKeyHex)
	}
	return b
}

func unmarshalRegisterPeerResponse(data []byte) *ExportPeerInfo {
	info := &ExportPeerInfo{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]
		switch {
		case typ == protowire.BytesType:
			s, n := protowire.ConsumeString(data)
			if n < 0 {
				return info
			}
			data = data[n:]
			switch num {
			case 1:
				info.AssignedIP = s
			case 2:
				info.ServerIP = s
			case 4:
				info.ServerPubKey = s
			}
		case num == 3 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return info
			}
			data = data[n:]
			info.ServerPort = int(v)
		default:
			n = protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return info
			}
			data = data[n:]
		}
	}
	return info
}
