//go:build linux

package platforms

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCPUSamplerNeedsTwoReadings(t *testing.T) {
	var s cpuSampler
	if _, ok := s.sample(1000, 800, true); ok {
		t.Fatal("first reading has no interval")
	}
	if got, ok := s.sample(1200, 850, true); !ok || got != 75 {
		t.Fatalf("200 jiffies, 50 idle → 75%%: %d %v", got, ok)
	}
	if _, ok := s.sample(100, 10, true); ok {
		t.Fatal("counter reset must not report")
	}
}

// The T2 that could not save settings: /overlay (ubifs, the config flash)
// at 100%. Root is the overlay mount, /tmp is RAM, /rom and /proc are not
// shown.
func TestReadVolumesKeepsTheFlashOverlay(t *testing.T) {
	mounts := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(mounts, []byte(`/dev/root /rom squashfs ro,relatime 0 0
proc /proc proc rw,nosuid 0 0
/dev/ubi0_3 /overlay ubifs rw,noatime 0 0
overlayfs:/overlay / overlay rw,noatime,lowerdir=/,upperdir=/overlay/upper 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noatime 0 0
`), 0o644); err != nil {
		t.Fatal(err)
	}
	sizes := map[string][3]uint64{"/overlay": {61132, 61132, 0}, "/": {61132, 61132, 0}, "/tmp": {884428, 30003, 854425}}
	volumes := readVolumes(mounts, func(path string) (uint64, uint64, uint64, bool) {
		v, ok := sizes[path]
		return v[0], v[1], v[2], ok
	})
	if len(volumes) != 3 {
		t.Fatalf("want /overlay, / and /tmp: %+v", volumes)
	}
	if v := volumes[0]; v.mount != "/overlay" || v.role != "Config" || v.fs != "ubifs" || v.availableKB != 0 || v.readOnly {
		t.Fatalf("config flash: %+v", v)
	}
	if volumes[2].role != "RAM" {
		t.Fatalf("tmp: %+v", volumes[2])
	}
}
