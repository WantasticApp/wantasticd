package wusp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const uspTransportVersion = 1

const (
	uspTransportKindRequest  = 1
	uspTransportKindResponse = 2
)

// USPAgentMethod identifies one USP operation carried over the WUSP control transport.
type USPAgentMethod uint8

const (
	USPAgentMethodGet USPAgentMethod = iota + 1
	USPAgentMethodSet
	USPAgentMethodDelete
	USPAgentMethodUpload
	USPAgentMethodDownload
)

type uspTransportHeader struct {
	Version uint8
	Kind    uint8
	Method  USPAgentMethod
	Flags   uint8
	ID      uint64
}

// USPAgentRequest is the on-the-wire request shape used over MessageWUSPType.
type USPAgentRequest struct {
	ID       uint64
	Method   USPAgentMethod
	Paths    []string
	Message  *Message
	Transfer *USPTransferRequest
}

// USPAgentResponse is the on-the-wire response shape used over MessageWUSPType.
type USPAgentResponse struct {
	ID       uint64
	Method   USPAgentMethod
	Message  *Message
	Transfer *USPTransferResult
	Error    string
}

var (
	ErrUSPTransportMalformed      = errors.New("wusp: malformed transport payload")
	ErrUSPTransportUnsupported    = errors.New("wusp: unsupported transport payload")
	ErrUSPTransportMethodRequired = errors.New("wusp: transport method required")
)

// HandleRequest executes a transport request against the agent and returns the response payload.
func (a *USPAgent) HandleRequest(ctx context.Context, req USPAgentRequest) (USPAgentResponse, error) {
	resp := USPAgentResponse{
		ID:     req.ID,
		Method: req.Method,
	}

	switch req.Method {
	case USPAgentMethodGet:
		msg, err := a.Get(req.Paths...)
		if err != nil {
			resp.Error = err.Error()
			return resp, nil
		}
		resp.Message = msg
		return resp, nil
	case USPAgentMethodSet:
		if req.Message == nil || len(req.Message.Fields) == 0 {
			resp.Error = "set request missing fields"
			return resp, nil
		}
		for _, field := range req.Message.Fields {
			if err := a.Set(field.Path, field.Val); err != nil {
				resp.Error = err.Error()
				return resp, nil
			}
		}
		return resp, nil
	case USPAgentMethodDelete:
		if len(req.Paths) == 0 {
			resp.Error = "delete request missing paths"
			return resp, nil
		}
		if err := a.Delete(req.Paths...); err != nil {
			resp.Error = err.Error()
			return resp, nil
		}
		return resp, nil
	case USPAgentMethodUpload:
		if req.Transfer == nil {
			resp.Error = "upload request missing transfer"
			return resp, nil
		}
		result, err := a.Upload(ctx, *req.Transfer)
		if err != nil {
			resp.Error = err.Error()
			return resp, nil
		}
		resp.Transfer = &result
		return resp, nil
	case USPAgentMethodDownload:
		if req.Transfer == nil {
			resp.Error = "download request missing transfer"
			return resp, nil
		}
		result, err := a.Download(ctx, *req.Transfer)
		if err != nil {
			resp.Error = err.Error()
			return resp, nil
		}
		resp.Transfer = &result
		return resp, nil
	default:
		return USPAgentResponse{}, fmt.Errorf("%w: method %d", ErrUSPTransportUnsupported, req.Method)
	}
}

func EncodeUSPAgentRequest(req USPAgentRequest) ([]byte, error) {
	if err := validateUSPAgentRequest(req); err != nil {
		return nil, err
	}

	transport := uspTransportBuffer{}
	header := uspTransportHeader{
		Version: uspTransportVersion,
		Kind:    uspTransportKindRequest,
		Method:  req.Method,
		ID:      req.ID,
	}
	if req.Message != nil {
		header.Flags |= 1 << 0
	}
	if req.Transfer != nil {
		header.Flags |= 1 << 1
	}
	transport.writeHeader(header)
	transport.writeStringList(req.Paths)
	if req.Message != nil {
		frame, err := encodeNestedMessage(req.Message)
		if err != nil {
			return nil, err
		}
		transport.writeBytes(frame)
	}
	if req.Transfer != nil {
		transport.writeTransferRequest(*req.Transfer)
	}
	return transport.bytes(), nil
}

func DecodeUSPAgentRequest(data []byte) (USPAgentRequest, error) {
	reader := newUSPTransportReader(data)
	header, err := reader.readHeader()
	if err != nil {
		return USPAgentRequest{}, err
	}
	if header.Kind != uspTransportKindRequest {
		return USPAgentRequest{}, fmt.Errorf("%w: unexpected request kind %d", ErrUSPTransportMalformed, header.Kind)
	}

	req := USPAgentRequest{
		ID:     header.ID,
		Method: header.Method,
	}
	req.Paths, err = reader.readStringList()
	if err != nil {
		return USPAgentRequest{}, err
	}
	if header.Flags&(1<<0) != 0 {
		msgFrame, err := reader.readBytes()
		if err != nil {
			return USPAgentRequest{}, err
		}
		req.Message, err = DecodeMessage(msgFrame)
		if err != nil {
			return USPAgentRequest{}, err
		}
	}
	if header.Flags&(1<<1) != 0 {
		transfer, err := reader.readTransferRequest()
		if err != nil {
			return USPAgentRequest{}, err
		}
		req.Transfer = &transfer
	}
	if !reader.done() && !reader.remainingAllZero() {
		return USPAgentRequest{}, fmt.Errorf("%w: trailing request data", ErrUSPTransportMalformed)
	}
	return req, validateUSPAgentRequest(req)
}

func EncodeUSPAgentResponse(resp USPAgentResponse) ([]byte, error) {
	if err := validateUSPAgentResponse(resp); err != nil {
		return nil, err
	}

	transport := uspTransportBuffer{}
	header := uspTransportHeader{
		Version: uspTransportVersion,
		Kind:    uspTransportKindResponse,
		Method:  resp.Method,
		ID:      resp.ID,
	}
	if resp.Message != nil {
		header.Flags |= 1 << 0
	}
	if resp.Transfer != nil {
		header.Flags |= 1 << 1
	}
	transport.writeHeader(header)
	transport.writeString(resp.Error)
	if resp.Message != nil {
		frame, err := encodeNestedMessage(resp.Message)
		if err != nil {
			return nil, err
		}
		transport.writeBytes(frame)
	}
	if resp.Transfer != nil {
		transport.writeTransferResult(*resp.Transfer)
	}
	return transport.bytes(), nil
}

func DecodeUSPAgentResponse(data []byte) (USPAgentResponse, error) {
	reader := newUSPTransportReader(data)
	header, err := reader.readHeader()
	if err != nil {
		return USPAgentResponse{}, err
	}
	if header.Kind != uspTransportKindResponse {
		return USPAgentResponse{}, fmt.Errorf("%w: unexpected response kind %d", ErrUSPTransportMalformed, header.Kind)
	}

	resp := USPAgentResponse{
		ID:     header.ID,
		Method: header.Method,
	}
	resp.Error, err = reader.readString()
	if err != nil {
		return USPAgentResponse{}, err
	}
	if header.Flags&(1<<0) != 0 {
		msgFrame, err := reader.readBytes()
		if err != nil {
			return USPAgentResponse{}, err
		}
		resp.Message, err = DecodeMessage(msgFrame)
		if err != nil {
			return USPAgentResponse{}, err
		}
	}
	if header.Flags&(1<<1) != 0 {
		transfer, err := reader.readTransferResult()
		if err != nil {
			return USPAgentResponse{}, err
		}
		resp.Transfer = &transfer
	}
	if !reader.done() && !reader.remainingAllZero() {
		return USPAgentResponse{}, fmt.Errorf("%w: trailing response data", ErrUSPTransportMalformed)
	}
	return resp, validateUSPAgentResponse(resp)
}

func validateUSPAgentRequest(req USPAgentRequest) error {
	if req.Method == 0 {
		return ErrUSPTransportMethodRequired
	}
	for _, path := range req.Paths {
		if strings.TrimSpace(path) == "" {
			return &ValidationError{Reason: "request contains empty path"}
		}
	}
	if req.Message != nil {
		if err := ValidateMessageFast(req.Message); err != nil {
			return err
		}
	}
	if req.Transfer != nil {
		if err := validateTransferRequest(*req.Transfer); err != nil {
			return err
		}
	}
	return nil
}

func validateUSPAgentResponse(resp USPAgentResponse) error {
	if resp.Method == 0 {
		return ErrUSPTransportMethodRequired
	}
	if resp.Message != nil {
		if err := ValidateMessageFast(resp.Message); err != nil {
			return err
		}
	}
	return nil
}

func encodeNestedMessage(msg *Message) ([]byte, error) {
	raw, err := EncodeMessage(msg)
	if err != nil {
		return nil, err
	}
	if len(raw) <= 512 {
		return raw, nil
	}
	return EncodeMessageLZ4(msg)
}

type uspTransportBuffer struct {
	buf []byte
}

func (b *uspTransportBuffer) bytes() []byte {
	return append([]byte(nil), b.buf...)
}

func (b *uspTransportBuffer) writeHeader(header uspTransportHeader) {
	b.buf = append(b.buf, header.Version, header.Kind, byte(header.Method), header.Flags)
	var id [8]byte
	binary.LittleEndian.PutUint64(id[:], header.ID)
	b.buf = append(b.buf, id[:]...)
}

func (b *uspTransportBuffer) writeUvarint(value uint64) {
	var tmp [10]byte
	n := binary.PutUvarint(tmp[:], value)
	b.buf = append(b.buf, tmp[:n]...)
}

func (b *uspTransportBuffer) writeString(value string) {
	b.writeUvarint(uint64(len(value)))
	b.buf = append(b.buf, value...)
}

func (b *uspTransportBuffer) writeBytes(value []byte) {
	b.writeUvarint(uint64(len(value)))
	b.buf = append(b.buf, value...)
}

func (b *uspTransportBuffer) writeStringList(values []string) {
	b.writeUvarint(uint64(len(values)))
	for _, value := range values {
		b.writeString(value)
	}
}

func (b *uspTransportBuffer) writeTransferRequest(req USPTransferRequest) {
	b.writeString(req.Path)
	b.writeString(req.URI)
	b.writeString(req.Filename)
	b.writeString(req.ContentType)
	b.writeBytes(req.Payload)
	b.writeMetadata(req.Metadata)
}

func (b *uspTransportBuffer) writeTransferResult(result USPTransferResult) {
	b.writeString(result.Path)
	b.writeString(result.URI)
	b.writeUvarint(uint64(result.Bytes))
	b.writeMetadata(result.Metadata)
}

func (b *uspTransportBuffer) writeMetadata(metadata map[string]string) {
	if len(metadata) == 0 {
		b.writeUvarint(0)
		return
	}
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	b.writeUvarint(uint64(len(keys)))
	for _, key := range keys {
		b.writeString(key)
		b.writeString(metadata[key])
	}
}

type uspTransportReader struct {
	data []byte
	pos  int
}

func newUSPTransportReader(data []byte) *uspTransportReader {
	return &uspTransportReader{data: data}
}

func (r *uspTransportReader) done() bool {
	return r.pos == len(r.data)
}

func (r *uspTransportReader) remainingAllZero() bool {
	for _, b := range r.data[r.pos:] {
		if b != 0 {
			return false
		}
	}
	r.pos = len(r.data)
	return true
}

func (r *uspTransportReader) readHeader() (uspTransportHeader, error) {
	if len(r.data) < 12 {
		return uspTransportHeader{}, fmt.Errorf("%w: payload too short", ErrUSPTransportMalformed)
	}
	header := uspTransportHeader{
		Version: r.data[0],
		Kind:    r.data[1],
		Method:  USPAgentMethod(r.data[2]),
		Flags:   r.data[3],
		ID:      binary.LittleEndian.Uint64(r.data[4:12]),
	}
	if header.Version != uspTransportVersion {
		return uspTransportHeader{}, fmt.Errorf("%w: version %d", ErrUSPTransportUnsupported, header.Version)
	}
	r.pos = 12
	return header, nil
}

func (r *uspTransportReader) readUvarint() (uint64, error) {
	value, n := binary.Uvarint(r.data[r.pos:])
	if n <= 0 {
		return 0, fmt.Errorf("%w: bad varint", ErrUSPTransportMalformed)
	}
	r.pos += n
	return value, nil
}

func (r *uspTransportReader) readString() (string, error) {
	data, err := r.readBytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *uspTransportReader) readBytes() ([]byte, error) {
	length, err := r.readUvarint()
	if err != nil {
		return nil, err
	}
	if length > uint64(len(r.data)-r.pos) {
		return nil, fmt.Errorf("%w: short blob", ErrUSPTransportMalformed)
	}
	value := append([]byte(nil), r.data[r.pos:r.pos+int(length)]...)
	r.pos += int(length)
	return value, nil
}

func (r *uspTransportReader) readStringList() ([]string, error) {
	count, err := r.readUvarint()
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		value, err := r.readString()
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func (r *uspTransportReader) readTransferRequest() (USPTransferRequest, error) {
	var req USPTransferRequest
	var err error
	if req.Path, err = r.readString(); err != nil {
		return USPTransferRequest{}, err
	}
	if req.URI, err = r.readString(); err != nil {
		return USPTransferRequest{}, err
	}
	if req.Filename, err = r.readString(); err != nil {
		return USPTransferRequest{}, err
	}
	if req.ContentType, err = r.readString(); err != nil {
		return USPTransferRequest{}, err
	}
	if req.Payload, err = r.readBytes(); err != nil {
		return USPTransferRequest{}, err
	}
	if req.Metadata, err = r.readMetadata(); err != nil {
		return USPTransferRequest{}, err
	}
	return req, nil
}

func (r *uspTransportReader) readTransferResult() (USPTransferResult, error) {
	var result USPTransferResult
	var err error
	if result.Path, err = r.readString(); err != nil {
		return USPTransferResult{}, err
	}
	if result.URI, err = r.readString(); err != nil {
		return USPTransferResult{}, err
	}
	if result.Bytes, err = r.readInt64AsUvarint(); err != nil {
		return USPTransferResult{}, err
	}
	if result.Metadata, err = r.readMetadata(); err != nil {
		return USPTransferResult{}, err
	}
	return result, nil
}

func (r *uspTransportReader) readInt64AsUvarint() (int64, error) {
	value, err := r.readUvarint()
	if err != nil {
		return 0, err
	}
	if value > uint64(^uint64(0)>>1) {
		return 0, io.ErrUnexpectedEOF
	}
	return int64(value), nil
}

func (r *uspTransportReader) readMetadata() (map[string]string, error) {
	count, err := r.readUvarint()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	metadata := make(map[string]string, count)
	for i := uint64(0); i < count; i++ {
		key, err := r.readString()
		if err != nil {
			return nil, err
		}
		value, err := r.readString()
		if err != nil {
			return nil, err
		}
		metadata[key] = value
	}
	return metadata, nil
}
