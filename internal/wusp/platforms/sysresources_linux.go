//go:build linux

package platforms

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"wantastic-agent/internal/wusp"
)

// appendSystemResources adds CPU usage since the previous collection and the
// device's filesystems. Both are passive reads (/proc/stat, /proc/mounts,
// statfs): nothing is sampled on a timer.
func appendSystemResources(msg *wusp.Message) {
	total, idle, read := readProcStat("/proc/stat")
	if usage, ok := hostCPU.sample(total, idle, read); ok {
		msg.Set("Device.DeviceInfo.ProcessStatus.CPUUsage", wusp.Uint(uint64(usage)))
	}
	appendStorageVolumes(msg, readVolumes("/proc/mounts", statfsKB))
}

var hostCPU cpuSampler

// cpuSampler turns two /proc/stat readings into a busy percentage.
type cpuSampler struct {
	mu          sync.Mutex
	total, idle uint64
}

func (s *cpuSampler) sample(total, idle uint64, ok bool) (uint32, bool) {
	if !ok {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prevTotal, prevIdle := s.total, s.idle
	s.total, s.idle = total, idle
	if prevTotal == 0 || total <= prevTotal || idle < prevIdle {
		return 0, false // first reading, or counters reset
	}
	dTotal, dIdle := total-prevTotal, idle-prevIdle
	if dIdle > dTotal {
		return 0, false
	}
	return uint32((dTotal - dIdle) * 100 / dTotal), true
}

// readProcStat returns the aggregate CPU jiffies and the idle part (idle +
// iowait) from /proc/stat's first line.
func readProcStat(path string) (total, idle uint64, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadString('\n')
	fields := strings.Fields(line)
	if err != nil && line == "" || len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i, field := range fields[1:] {
		v, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		total += v
		if i == 3 || i == 4 { // idle, iowait
			idle += v
		}
	}
	return total, idle, true
}

type storageVolume struct {
	mount, fs, role              string
	totalKB, usedKB, availableKB uint64
	readOnly                     bool
}

// volumeRole names the filesystems worth showing; others (/proc, /sys,
// squashfs /rom, cgroups, per-service tmpfs) are skipped.
func volumeRole(mount, fs string) string {
	switch {
	case mount == "/":
		return "Root"
	case mount == "/overlay":
		return "Config"
	case mount == "/data" || mount == "/usrdata" || mount == "/opt" || mount == "/home":
		return "Data"
	case mount == "/tmp" && fs == "tmpfs":
		return "RAM"
	}
	return ""
}

func readVolumes(mountsPath string, statfs func(string) (total, used, avail uint64, ok bool)) []storageVolume {
	f, err := os.Open(mountsPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	byMount := map[string]int{}
	var out []storageVolume
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		mount, fs := fields[1], fields[2]
		role := volumeRole(mount, fs)
		if role == "" || fs == "rootfs" {
			continue
		}
		total, used, avail, ok := statfs(mount)
		if !ok || total == 0 {
			continue
		}
		v := storageVolume{mount: mount, fs: fs, role: role, totalKB: total, usedKB: used, availableKB: avail, readOnly: strings.HasPrefix(fields[3], "ro,") || fields[3] == "ro"}
		if i, seen := byMount[mount]; seen {
			out[i] = v // the last mount on a path is the visible one
			continue
		}
		byMount[mount] = len(out)
		out = append(out, v)
	}
	return out
}

func statfsKB(path string) (total, used, avail uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, false
	}
	bsize := uint64(st.Bsize)
	total = st.Blocks * bsize / 1024
	free := st.Bfree * bsize / 1024
	if free > total {
		free = total
	}
	return total, total - free, st.Bavail * bsize / 1024, true
}

func appendStorageVolumes(msg *wusp.Message, volumes []storageVolume) {
	if len(volumes) == 0 {
		return
	}
	msg.Set(wusp.WUSPStoragePrefix+"VolumeNumberOfEntries", wusp.Uint(uint64(len(volumes))))
	for i, v := range volumes {
		prefix := wusp.WUSPStoragePrefix + "Volume." + strconv.Itoa(i+1) + "."
		msg.Set(prefix+"MountPoint", wusp.String(v.mount))
		msg.Set(prefix+"FileSystem", wusp.String(v.fs))
		msg.Set(prefix+"Role", wusp.String(v.role))
		msg.Set(prefix+"TotalKB", wusp.Uint(v.totalKB))
		msg.Set(prefix+"UsedKB", wusp.Uint(v.usedKB))
		msg.Set(prefix+"AvailableKB", wusp.Uint(v.availableKB))
		msg.Set(prefix+"ReadOnly", wusp.Bool(v.readOnly))
	}
}
