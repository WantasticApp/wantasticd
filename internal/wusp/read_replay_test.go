package wusp

import (
	"reflect"
	"testing"
)

func TestFragmentIndexSetRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		indices []uint32
		want    string
	}{
		{"single", []uint32{4}, "4"},
		{"run", []uint32{0, 1, 2, 3}, "0-3"},
		{"mixed unsorted with duplicates", []uint32{9, 7, 0, 1, 2, 3, 10, 7}, "0-3,7,9-10"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatFragmentIndexSet(tc.indices)
			if got != tc.want {
				t.Fatalf("FormatFragmentIndexSet = %q, want %q", got, tc.want)
			}
			parsed, err := ParseFragmentIndexSet(got)
			if err != nil {
				t.Fatalf("ParseFragmentIndexSet(%q): %v", got, err)
			}
			want := make(map[uint32]struct{})
			for _, index := range tc.indices {
				want[index] = struct{}{}
			}
			if !reflect.DeepEqual(parsed, want) {
				t.Fatalf("parsed %v, want %v", parsed, want)
			}
		})
	}
}

func TestParseFragmentIndexSetRejectsGarbage(t *testing.T) {
	for _, raw := range []string{"a", "3-1", "1-x", "70000"} {
		if _, err := ParseFragmentIndexSet(raw); err == nil {
			t.Fatalf("ParseFragmentIndexSet(%q) accepted garbage", raw)
		}
	}
	if _, ok := ResendFragments(map[string]string{MetadataKeyResendFragments: "3-1"}); ok {
		t.Fatal("a garbled resend list must fall back to the whole reply")
	}
}

func TestReadReplayMetadata(t *testing.T) {
	if SupportsReadReplay(nil) {
		t.Fatal("nil metadata advertised read replay")
	}
	md := WithReadReplay(map[string]string{"x": "y"})
	if !SupportsReadReplay(md) || md["x"] != "y" {
		t.Fatalf("WithReadReplay = %v", md)
	}
	miss := WithReadReplayMiss(nil)
	if !SupportsReadReplay(miss) || !IsReadReplayMiss(miss) || IsReadReplayMiss(md) {
		t.Fatalf("miss metadata = %v", miss)
	}
	req := WithResendFragments(nil, []uint32{2, 5, 3})
	set, ok := ResendFragments(req)
	if !ok || len(set) != 3 {
		t.Fatalf("ResendFragments = %v %v", set, ok)
	}
	if cleared := WithResendFragments(req, nil); cleared[MetadataKeyResendFragments] != "" {
		t.Fatalf("empty resend list must clear the key: %v", cleared)
	}
	if !IsReadReplayMethod(USPAgentMethodGet) || !IsReadReplayMethod(USPAgentMethodGetInstances) || IsReadReplayMethod(USPAgentMethodSet) {
		t.Fatal("IsReadReplayMethod classification")
	}
}
