package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

const (
	uspRecommendedChunkSize = wusp.USPRecommendedChunkSize
	uspTransferWindowSize   = 8
	uspTransferAckTimeout   = 2 * time.Second
)

type uspTransferSession struct {
	id               uint64
	requestID        uint64
	method           wusp.USPAgentMethod
	peerPublicKeyHex string
	send             func([]byte) error
	path             string
	file             *os.File
	writer           *bufio.Writer
	totalSize        int64
	transferred      int64
	nextSequence     uint32
	ackCh            chan uint32
}

func (r *uspRuntime) handleTransferControlRequest(ctx context.Context, peerPublicKeyHex string, req wusp.USPAgentRequest, reply func([]byte) error) error {
	if req.Transfer == nil {
		frame, _ := wusp.EncodeUSPAgentResponse(wusp.USPAgentResponse{
			ID:     req.ID,
			Method: req.Method,
			Error:  "transfer request missing transfer block",
		})
		return reply(frame)
	}
	if reply == nil {
		return fmt.Errorf("missing reply transport for transfer request %d", req.ID)
	}

	switch req.Method {
	case wusp.USPAgentMethodUpload:
		session, result, err := r.startUploadSession(req, peerPublicKeyHex, reply)
		if err != nil {
			frame, _ := wusp.EncodeUSPAgentResponse(wusp.USPAgentResponse{
				ID:     req.ID,
				Method: req.Method,
				Error:  err.Error(),
			})
			return reply(frame)
		}
		r.streams.Store(session.id, session)
		frame, err := wusp.EncodeUSPAgentResponse(wusp.USPAgentResponse{
			ID:       req.ID,
			Method:   req.Method,
			Transfer: &result,
		})
		if err != nil {
			return err
		}
		return reply(frame)
	case wusp.USPAgentMethodDownload:
		session, result, err := r.startDownloadSession(req, peerPublicKeyHex, reply)
		if err != nil {
			frame, _ := wusp.EncodeUSPAgentResponse(wusp.USPAgentResponse{
				ID:     req.ID,
				Method: req.Method,
				Error:  err.Error(),
			})
			return reply(frame)
		}
		r.streams.Store(session.id, session)
		frame, err := wusp.EncodeUSPAgentResponse(wusp.USPAgentResponse{
			ID:       req.ID,
			Method:   req.Method,
			Transfer: &result,
		})
		if err != nil {
			return err
		}
		if err := reply(frame); err != nil {
			r.streams.Delete(session.id)
			return err
		}
		go r.streamDownloadSession(context.Background(), session, req.Transfer)
		return nil
	default:
		return fmt.Errorf("unsupported transfer method %d", req.Method)
	}
}

func (r *uspRuntime) startUploadSession(req wusp.USPAgentRequest, peerPublicKeyHex string, send func([]byte) error) (*uspTransferSession, wusp.USPTransferResult, error) {
	targetPath := firstNonEmpty(localPathFromURI(req.Transfer.URI), strings.TrimSpace(req.Transfer.Metadata["destination"]), strings.TrimSpace(req.Transfer.Filename))
	if targetPath == "" {
		targetPath = filepath.Join(r.transferDirectory(), sanitizeTransferName(req.Transfer.Path)+".upload")
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return nil, wusp.USPTransferResult{}, err
	}
	file, err := os.Create(targetPath)
	if err != nil {
		return nil, wusp.USPTransferResult{}, err
	}
	totalSize := parseTransferSize(req.Transfer.Metadata["size"])
	session := &uspTransferSession{
		id:               r.nextID.Add(1),
		requestID:        req.ID,
		method:           req.Method,
		peerPublicKeyHex: peerPublicKeyHex,
		send:             send,
		path:             targetPath,
		file:             file,
		writer:           bufio.NewWriterSize(file, uspRecommendedChunkSize*uspTransferWindowSize),
		totalSize:        totalSize,
		nextSequence:     1,
		ackCh:            make(chan uint32, uspTransferWindowSize*2),
	}
	result := wusp.USPTransferResult{
		Path:  req.Transfer.Path,
		URI:   "file://" + targetPath,
		Bytes: 0,
		Metadata: map[string]string{
			"transport":   "wg-stream",
			"session_id":  strconv.FormatUint(session.id, 10),
			"chunk_size":  strconv.Itoa(uspRecommendedChunkSize),
			"destination": targetPath,
		},
	}
	return session, result, nil
}

func (r *uspRuntime) startDownloadSession(req wusp.USPAgentRequest, peerPublicKeyHex string, send func([]byte) error) (*uspTransferSession, wusp.USPTransferResult, error) {
	sourcePath := firstNonEmpty(localPathFromURI(req.Transfer.URI), strings.TrimSpace(req.Transfer.Metadata["source"]), strings.TrimSpace(req.Transfer.Filename))
	if sourcePath == "" {
		return nil, wusp.USPTransferResult{}, fmt.Errorf("download source not provided for tunnel transfer")
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return nil, wusp.USPTransferResult{}, err
	}
	session := &uspTransferSession{
		id:               r.nextID.Add(1),
		requestID:        req.ID,
		method:           req.Method,
		peerPublicKeyHex: peerPublicKeyHex,
		send:             send,
		path:             sourcePath,
		totalSize:        info.Size(),
		nextSequence:     1,
		ackCh:            make(chan uint32, uspTransferWindowSize*2),
	}
	result := wusp.USPTransferResult{
		Path:  req.Transfer.Path,
		URI:   "file://" + sourcePath,
		Bytes: info.Size(),
		Metadata: map[string]string{
			"transport":  "wg-stream",
			"session_id": strconv.FormatUint(session.id, 10),
			"chunk_size": strconv.Itoa(uspRecommendedChunkSize),
			"source":     sourcePath,
		},
	}
	return session, result, nil
}

func (r *uspRuntime) handleTransferStreamFrame(peerPublicKeyHex string, frame wusp.USPTransferStreamFrame) error {
	value, ok := r.streams.Load(frame.SessionID)
	if !ok {
		return fmt.Errorf("unknown transfer stream session %d", frame.SessionID)
	}
	session, ok := value.(*uspTransferSession)
	if !ok {
		return fmt.Errorf("invalid transfer session %d", frame.SessionID)
	}
	if !strings.EqualFold(session.peerPublicKeyHex, peerPublicKeyHex) {
		return fmt.Errorf("transfer stream session %d from unauthorized peer", frame.SessionID)
	}

	switch session.method {
	case wusp.USPAgentMethodUpload:
		return r.handleUploadStreamFrame(session, frame)
	case wusp.USPAgentMethodDownload:
		return r.handleDownloadStreamFrame(session, frame)
	default:
		return fmt.Errorf("unsupported session method %d", session.method)
	}
}

func (r *uspRuntime) handleUploadStreamFrame(session *uspTransferSession, frame wusp.USPTransferStreamFrame) error {
	switch frame.Phase {
	case wusp.USPTransferStreamOpen:
		return session.sendStream(wusp.USPTransferStreamFrame{
			SessionID:   session.id,
			RequestID:   session.requestID,
			Method:      session.method,
			Phase:       wusp.USPTransferStreamAck,
			AckSequence: 0,
			Offset:      uint64(session.transferred),
			TotalSize:   uint64(maxInt64(session.totalSize, 0)),
		})
	case wusp.USPTransferStreamChunk:
		if frame.Sequence != session.nextSequence {
			return session.sendStream(wusp.USPTransferStreamFrame{
				SessionID:   session.id,
				RequestID:   session.requestID,
				Method:      session.method,
				Phase:       wusp.USPTransferStreamAck,
				AckSequence: session.nextSequence - 1,
				Offset:      uint64(session.transferred),
				TotalSize:   uint64(maxInt64(session.totalSize, 0)),
			})
		}
		if session.file == nil {
			return fmt.Errorf("upload session %d missing target file", session.id)
		}
		writer := session.writer
		if writer == nil {
			writer = bufio.NewWriterSize(session.file, uspRecommendedChunkSize*uspTransferWindowSize)
			session.writer = writer
		}
		written, err := writer.Write(frame.Data)
		if err != nil {
			return err
		}
		if frame.Final {
			if err := writer.Flush(); err != nil {
				return err
			}
		}
		session.transferred += int64(written)
		session.nextSequence++
		return session.sendStream(wusp.USPTransferStreamFrame{
			SessionID:   session.id,
			RequestID:   session.requestID,
			Method:      session.method,
			Phase:       wusp.USPTransferStreamAck,
			AckSequence: frame.Sequence,
			Offset:      uint64(session.transferred),
			TotalSize:   uint64(maxInt64(session.totalSize, 0)),
			Final:       frame.Final,
		})
	case wusp.USPTransferStreamComplete:
		if session.writer != nil {
			if err := session.writer.Flush(); err != nil {
				return err
			}
		}
		if session.file != nil {
			_ = session.file.Close()
			session.file = nil
		}
		session.writer = nil
		r.streams.Delete(session.id)
		return session.sendStream(wusp.USPTransferStreamFrame{
			SessionID:   session.id,
			RequestID:   session.requestID,
			Method:      session.method,
			Phase:       wusp.USPTransferStreamComplete,
			AckSequence: session.nextSequence - 1,
			Offset:      uint64(session.transferred),
			TotalSize:   uint64(maxInt64(session.totalSize, session.transferred)),
			Final:       true,
			Metadata: map[string]string{
				"destination": session.path,
			},
		})
	case wusp.USPTransferStreamAbort:
		if session.writer != nil {
			_ = session.writer.Flush()
			session.writer = nil
		}
		if session.file != nil {
			_ = session.file.Close()
			session.file = nil
		}
		r.streams.Delete(session.id)
		_ = os.Remove(session.path)
		return nil
	default:
		return nil
	}
}

func (r *uspRuntime) handleDownloadStreamFrame(session *uspTransferSession, frame wusp.USPTransferStreamFrame) error {
	if frame.Phase != wusp.USPTransferStreamAck {
		return nil
	}
	select {
	case session.ackCh <- frame.AckSequence:
	default:
	}
	return nil
}

func (r *uspRuntime) streamDownloadSession(ctx context.Context, session *uspTransferSession, req *wusp.USPTransferRequest) {
	source, err := os.Open(session.path)
	if err != nil {
		r.streams.Delete(session.id)
		return
	}
	defer source.Close()
	defer r.streams.Delete(session.id)

	_ = session.sendStream(wusp.USPTransferStreamFrame{
		SessionID:   session.id,
		RequestID:   session.requestID,
		Method:      session.method,
		Phase:       wusp.USPTransferStreamOpen,
		Path:        req.Path,
		Filename:    filepath.Base(session.path),
		ContentType: req.ContentType,
		TotalSize:   uint64(maxInt64(session.totalSize, 0)),
	})

	buf := make([]byte, uspRecommendedChunkSize)
	pending := make(map[uint32]uspTransferPendingChunk, uspTransferWindowSize)
	for {
		for len(pending) < uspTransferWindowSize {
			n, readErr := source.Read(buf)
			if n > 0 {
				payload := append([]byte(nil), buf[:n]...)
				frame := wusp.USPTransferStreamFrame{
					SessionID: session.id,
					RequestID: session.requestID,
					Method:    session.method,
					Phase:     wusp.USPTransferStreamChunk,
					Sequence:  session.nextSequence,
					Offset:    uint64(session.transferred + pendingTransferredBytes(pending)),
					TotalSize: uint64(maxInt64(session.totalSize, 0)),
					Data:      payload,
					Final:     readErr == io.EOF,
				}
				pending[frame.Sequence] = uspTransferPendingChunk{frame: frame, size: n}
				if err := session.sendStream(frame); err != nil {
					return
				}
				session.nextSequence++
			}
			if readErr == io.EOF {
				goto waitPending
			}
			if readErr != nil {
				return
			}
		}

	waitPending:
		if len(pending) == 0 {
			break
		}
		ackSequence, err := session.waitForAnyAck(ctx)
		if err != nil {
			if !resendPendingChunks(session, pending) {
				return
			}
			continue
		}
		session.transferred += releaseAckedPendingChunks(pending, ackSequence)
	}

	_ = session.sendStream(wusp.USPTransferStreamFrame{
		SessionID:   session.id,
		RequestID:   session.requestID,
		Method:      session.method,
		Phase:       wusp.USPTransferStreamComplete,
		AckSequence: session.nextSequence - 1,
		Offset:      uint64(session.transferred),
		TotalSize:   uint64(maxInt64(session.totalSize, session.transferred)),
		Final:       true,
		Metadata: map[string]string{
			"source": session.path,
		},
	})
}

func (s *uspTransferSession) sendStream(frame wusp.USPTransferStreamFrame) error {
	if s == nil || s.send == nil {
		return fmt.Errorf("transfer stream transport unavailable")
	}
	payload, err := wusp.EncodeUSPTransferStreamFrame(frame)
	if err != nil {
		return err
	}
	return s.send(payload)
}

func parseTransferSize(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func maxInt64(values ...int64) int64 {
	var max int64
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

type uspTransferPendingChunk struct {
	frame wusp.USPTransferStreamFrame
	size  int
}

func (s *uspTransferSession) waitForAnyAck(ctx context.Context) (uint32, error) {
	waitCtx, cancel := context.WithTimeout(ctx, uspTransferAckTimeout)
	defer cancel()

	select {
	case <-waitCtx.Done():
		return 0, waitCtx.Err()
	case ackSequence := <-s.ackCh:
		return ackSequence, nil
	}
}

func resendPendingChunks(session *uspTransferSession, pending map[uint32]uspTransferPendingChunk) bool {
	sequences := make([]uint32, 0, len(pending))
	for sequence := range pending {
		sequences = append(sequences, sequence)
	}
	slices.Sort(sequences)
	for _, sequence := range sequences {
		if err := session.sendStream(pending[sequence].frame); err != nil {
			return false
		}
	}
	return true
}

func releaseAckedPendingChunks(pending map[uint32]uspTransferPendingChunk, ackSequence uint32) int64 {
	var released int64
	for sequence, chunk := range pending {
		if sequence <= ackSequence {
			released += int64(chunk.size)
			delete(pending, sequence)
		}
	}
	return released
}

func pendingTransferredBytes(pending map[uint32]uspTransferPendingChunk) int64 {
	var total int64
	for _, chunk := range pending {
		total += int64(chunk.size)
	}
	return total
}
