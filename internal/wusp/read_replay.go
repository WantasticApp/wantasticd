package wusp

import (
	"sort"
	"strconv"
	"strings"
)

// Read replay lets a controller recover a lost fragment of a large Get or
// GetInstances reply without the agent re-collecting or re-sending the whole
// reply. An agent that keeps its encoded read replies for a short time marks
// every response with MetadataKeyReadReplay. The controller then retries a read
// with the same request ID and sequence, listing the fragment indices it is
// still missing in MetadataKeyResendFragments; the agent answers from the kept
// reply with exactly the same fragmentation, so the controller completes the
// message from the fragments of both attempts.
//
// Both keys are plain request/response metadata: an older agent ignores
// MetadataKeyResendFragments and an older controller ignores
// MetadataKeyReadReplay, so neither side needs a protocol version bump.
//
// Keep this file identical in the controller (ISPApp-TunnelHub) and agent
// (wantasticd) copies of package wusp.
const (
	MetadataKeyReadReplay      = "wusp.read_replay"
	MetadataKeyResendFragments = "wusp.resend_fragments"
	readReplayEnabled          = "1"
	readReplayMiss             = "miss"
	maxResendFragmentRanges    = 256
)

// WithReadReplay marks response metadata as coming from an agent that can
// replay read replies.
func WithReadReplay(metadata map[string]string) map[string]string {
	out := CloneMetadata(metadata)
	if out == nil {
		out = make(map[string]string, 1)
	}
	out[MetadataKeyReadReplay] = readReplayEnabled
	return out
}

// WithReadReplayMiss marks a response that answers a resend request for a
// reply the agent no longer keeps. The controller must then drop the
// fragments it holds and ask again under a new request ID.
func WithReadReplayMiss(metadata map[string]string) map[string]string {
	out := CloneMetadata(metadata)
	if out == nil {
		out = make(map[string]string, 1)
	}
	out[MetadataKeyReadReplay] = readReplayMiss
	return out
}

// SupportsReadReplay reports whether response metadata advertises read replay.
func SupportsReadReplay(metadata map[string]string) bool {
	value := strings.TrimSpace(metadata[MetadataKeyReadReplay])
	return value == readReplayEnabled || value == readReplayMiss
}

// IsReadReplayMiss reports whether a response says the agent could not replay
// the requested reply.
func IsReadReplayMiss(metadata map[string]string) bool {
	return strings.TrimSpace(metadata[MetadataKeyReadReplay]) == readReplayMiss
}

// IsReadReplayMethod reports whether method is a read whose reply an agent may
// keep and replay by request identity.
func IsReadReplayMethod(method USPAgentMethod) bool {
	return method == USPAgentMethodGet || method == USPAgentMethodGetInstances
}

// WithResendFragments asks the agent to re-send only the listed fragment
// indices of an earlier reply. An empty list removes the key, which asks for
// the whole reply.
func WithResendFragments(metadata map[string]string, indices []uint32) map[string]string {
	out := CloneMetadata(metadata)
	if len(indices) == 0 {
		delete(out, MetadataKeyResendFragments)
		return out
	}
	if out == nil {
		out = make(map[string]string, 1)
	}
	out[MetadataKeyResendFragments] = FormatFragmentIndexSet(indices)
	return out
}

// ResendFragments returns the fragment indices a request asks to be re-sent.
// ok is false when the request asks for the whole reply (no key, or a value
// that cannot be parsed, which is treated the same way so a garbled list can
// only cost bandwidth, never correctness).
func ResendFragments(metadata map[string]string) (map[uint32]struct{}, bool) {
	raw := strings.TrimSpace(metadata[MetadataKeyResendFragments])
	if raw == "" {
		return nil, false
	}
	set, err := ParseFragmentIndexSet(raw)
	if err != nil || len(set) == 0 {
		return nil, false
	}
	return set, true
}

// FormatFragmentIndexSet renders indices as a compact sorted range list, e.g.
// "0-3,7,9-10".
func FormatFragmentIndexSet(indices []uint32) string {
	if len(indices) == 0 {
		return ""
	}
	sorted := append([]uint32(nil), indices...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var b strings.Builder
	start, prev := sorted[0], sorted[0]
	flush := func() {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(start), 10))
		if prev != start {
			b.WriteByte('-')
			b.WriteString(strconv.FormatUint(uint64(prev), 10))
		}
	}
	for _, index := range sorted[1:] {
		if index == prev {
			continue
		}
		if index == prev+1 {
			prev = index
			continue
		}
		flush()
		start, prev = index, index
	}
	flush()
	return b.String()
}

// ParseFragmentIndexSet parses a FormatFragmentIndexSet range list.
func ParseFragmentIndexSet(raw string) (map[uint32]struct{}, error) {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	if len(parts) > maxResendFragmentRanges {
		return nil, &ValidationError{Reason: "too many resend fragment ranges"}
	}
	out := make(map[uint32]struct{})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, found := strings.Cut(part, "-")
		start, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 32)
		if err != nil {
			return nil, &ValidationError{Reason: "invalid resend fragment index"}
		}
		end := start
		if found {
			end, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 32)
			if err != nil || end < start {
				return nil, &ValidationError{Reason: "invalid resend fragment range"}
			}
		}
		if end >= MaxUSPControlFragmentCount {
			return nil, &ValidationError{Reason: "resend fragment index too large"}
		}
		for index := start; index <= end; index++ {
			out[uint32(index)] = struct{}{}
		}
	}
	return out, nil
}
