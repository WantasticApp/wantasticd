package grpc

// This file hand-crafts the protobuf wire encoding for RegisterDeviceRequest
// and RegisterDeviceResponse using spec-correct field numbers:
//
//	RegisterDeviceRequest  RegisterDeviceResponse
//	─────────────────────  ──────────────────────
//	token    = 1 (string)  success          = 1 (bool)
//	hostname = 2 (string)  token            = 2 (string)
//	os       = 3 (string)  server_key       = 3 (string)
//	arch     = 4 (string)  endpoint         = 4 (string)
//	nonce    = 5 (uint64)  allowed_ips      = 5 (repeated string)
//	                       persistent_keepalive = 6 (int32)
//	                       mtu              = 7 (int32)
//	                       listen_port      = 8 (int32)
//	                       encrypted_config = 9 (bytes)   ← critical
//	                       routes           = 10 (repeated string)
//	                       dns_servers      = 11 (repeated string)
//	                       forwarding_rules = 12 (repeated string)
//
// The generated auth.pb.go has mismatched field numbers (e.g. encrypted_config
// at field 12 instead of 9) because it pre-dates the spec finalisation.
// Regenerating requires protoc; this file avoids that dependency.

import (
	"google.golang.org/protobuf/encoding/protowire"

	pb "wantastic-agent/internal/grpc/proto"
)

// marshalRegisterDeviceRequest serialises a RegisterDeviceRequest message
// using the spec-correct field numbers. device_id (field 6) is the plain
// hardware machine ID (UUID on macOS) — the same value sent as the
// device_id param in the PKCE OAuth authorize URL.
func marshalRegisterDeviceRequest(token, hostname, osStr, arch, deviceID string, nonce uint64) []byte {
	var b []byte

	if token != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, token)
	}
	if hostname != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, hostname)
	}
	if osStr != "" {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendString(b, osStr)
	}
	if arch != "" {
		b = protowire.AppendTag(b, 4, protowire.BytesType)
		b = protowire.AppendString(b, arch)
	}
	if nonce != 0 {
		b = protowire.AppendTag(b, 5, protowire.VarintType)
		b = protowire.AppendVarint(b, nonce)
	}
	if deviceID != "" {
		b = protowire.AppendTag(b, 6, protowire.BytesType)
		b = protowire.AppendString(b, deviceID)
	}

	return b
}

// unmarshalRegisterDeviceResponse parses raw protobuf bytes from the server
// into a *pb.RegisterDeviceResponse, using the spec-correct field numbers.
// Fields 1-6 are the same as the existing generated type; fields 7-9 differ.
func unmarshalRegisterDeviceResponse(data []byte) *pb.RegisterDeviceResponse {
	r := &pb.RegisterDeviceResponse{}

	for len(data) > 0 {
		fieldNum, wireType, n := protowire.ConsumeTag(data)
		if n < 0 {
			break
		}
		data = data[n:]

		switch wireType {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			switch fieldNum {
			case 1: // success
				r.Success = v != 0
			case 6: // persistent_keepalive
				r.PersistentKeepalive = int32(v)
			case 7: // mtu  (spec field 7, was 10 in old proto)
				r.Mtu = int32(v)
			case 8: // listen_port (spec field 8, was 11)
				r.ListenPort = int32(v)
			}

		case protowire.BytesType:
			b, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return r
			}
			data = data[n:]
			s := string(b)
			switch fieldNum {
			case 2: // token
				r.Token = s
			case 3: // server_key
				r.ServerKey = s
			case 4: // endpoint
				r.Endpoint = s
			case 5: // allowed_ips (repeated)
				r.AllowedIps = append(r.AllowedIps, s)
			case 9: // encrypted_config (spec field 9, was 12 in old proto) ← KEY FIX
				r.EncryptedConfig = append(r.EncryptedConfig[:0], b...)
			case 10: // routes
				r.Routes = append(r.Routes, s)
			case 11: // dns_servers
				r.DnsServers = append(r.DnsServers, s)
			case 12: // forwarding_rules
				r.ForwardingRules = append(r.ForwardingRules, s)
			}

		default:
			// Skip unknown wire types gracefully
			n := protowire.ConsumeFieldValue(fieldNum, wireType, data)
			if n < 0 {
				return r
			}
			data = data[n:]
		}
	}

	return r
}
