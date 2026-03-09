package grpc

// rawCodec overrides the default "proto" gRPC codec so that we can pass raw
// pre-serialised protobuf bytes through gRPC without going through the
// protobuf-go v2 descriptor-driven marshal path.
//
// This is necessary because the proto/auth.pb.go file was generated with
// incorrect field numbers for RegisterDeviceRequest/RegisterDeviceResponse.
// Regenerating requires protoc and the Go plugins; to avoid that hard
// dependency we manually encode/decode those two messages using
// google.golang.org/protobuf/encoding/protowire (see register_device_wire.go)
// and hand the raw bytes to gRPC through this codec shim.

import (
	"fmt"

	"google.golang.org/grpc/encoding"
	googleproto "google.golang.org/protobuf/proto"
)

// rawProtoMessage is a byte slice that is passed verbatim as a gRPC request or
// response body, bypassing the normal proto.Marshal / proto.Unmarshal calls.
type rawProtoMessage []byte

func (r rawProtoMessage) ProtoMessage()  {}
func (r rawProtoMessage) Reset()         {}
func (r rawProtoMessage) String() string { return fmt.Sprintf("rawProtoMessage(%d bytes)", len(r)) }

// rawCodec implements encoding.Codec and acts as a transparent proxy for
// normal proto.Message values while short-circuiting rawProtoMessage values.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v interface{}) ([]byte, error) {
	if raw, ok := v.(rawProtoMessage); ok {
		return []byte(raw), nil
	}
	if raw, ok := v.(*rawProtoMessage); ok && raw != nil {
		return []byte(*raw), nil
	}
	if m, ok := v.(googleproto.Message); ok {
		return googleproto.Marshal(m)
	}
	return nil, fmt.Errorf("rawCodec: cannot marshal %T", v)
}

func (rawCodec) Unmarshal(data []byte, v interface{}) error {
	if raw, ok := v.(*rawProtoMessage); ok {
		*raw = append((*raw)[:0], data...)
		return nil
	}
	if m, ok := v.(googleproto.Message); ok {
		return googleproto.Unmarshal(data, m)
	}
	return fmt.Errorf("rawCodec: cannot unmarshal into %T", v)
}

var rawCodecRegistered bool

// initRawCodec replaces the default "proto" codec with rawCodec.
// Called from the package init() so it takes effect before any gRPC clients
// are created.
func initRawCodec() {
	if !rawCodecRegistered {
		encoding.RegisterCodec(rawCodec{})
		rawCodecRegistered = true
	}
}

func init() {
	initRawCodec()
}
