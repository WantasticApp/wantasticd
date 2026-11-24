package endpoints

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"wantastic-agent/internal/oltd/cemu"
	"wantastic-agent/internal/oltd/sysx"
)

// readFile reads at most max bytes of a local file with raw syscalls
// (os.Open would initialize the Go network poller on Linux).
func readFile(env *Env, path string, max int) ([]byte, bool) {
	if env != nil && env.Root != "" {
		path = env.Root + path
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, false
	}
	defer syscall.Close(fd)
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < max {
		n, err := syscall.Read(fd, tmp)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, false
		}
		if n <= 0 {
			break
		}
		buf = append(buf, tmp[:n]...)
	}
	if len(buf) > max {
		buf = buf[:max]
	}
	return buf, true
}

// localTimeString formats like system_time(): strftime("%Y-%m-%d %H:%M:%S")
// of localtime_r. uClibc takes the zone from $TZ or /etc/TZ (a POSIX TZ
// string); Go reads $TZ or /etc/localtime, so /etc/TZ is honoured here.
func localTimeString(env *Env, now time.Time) string {
	loc := time.Local
	if os.Getenv("TZ") == "" {
		if raw, ok := readFile(env, "/etc/TZ", 256); ok {
			if z := posixZone(strings.TrimSpace(string(raw))); z != nil {
				loc = z
			}
		}
	}
	return now.In(loc).Format("2006-01-02 15:04:05")
}

// posixZone parses the standard-time part of a POSIX TZ string
// ("CST-8", "UTC+3:30"). DST rules are ignored.
func posixZone(tz string) *time.Location {
	i := 0
	if strings.HasPrefix(tz, "<") {
		j := strings.IndexByte(tz, '>')
		if j < 0 {
			return nil
		}
		i = j + 1
	} else {
		for i < len(tz) && (tz[i] < '0' || tz[i] > '9') && tz[i] != '+' && tz[i] != '-' {
			i++
		}
	}
	name := strings.Trim(tz[:i], "<>")
	rest := tz[i:]
	if rest == "" {
		return nil
	}
	sign := 1
	if rest[0] == '+' || rest[0] == '-' {
		if rest[0] == '-' {
			sign = -1
		}
		rest = rest[1:]
	}
	end := 0
	for end < len(rest) && ((rest[end] >= '0' && rest[end] <= '9') || rest[end] == ':') {
		end++
	}
	parts := strings.Split(rest[:end], ":")
	secs := 0
	mult := []int{3600, 60, 1}
	for k, p := range parts {
		if k > 2 || p == "" {
			break
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		secs += v * mult[k]
	}
	// POSIX offsets are west-positive.
	return time.FixedZone(name, -sign*secs)
}

type cpuSample struct {
	mu          sync.Mutex
	total, idle uint64
	have        bool
}

func readCPU(env *Env) (total, idle uint64, ok bool) {
	raw, ok := readFile(env, "/proc/stat", 4096)
	if !ok {
		return 0, 0, false
	}
	line := string(raw)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, false
	}
	for k, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if k == 3 || k == 4 { // idle + iowait
			idle += n
		}
	}
	return total, idle, true
}

// cpuPercent is the busy share of all CPU time since the previous call
// (first call: over a 200 ms nanosleep window), from /proc/stat like
// libfos pal_get_cpu_usage. Native equivalent, not bit-exact.
func cpuPercent(env *Env) uint {
	s := &env.sysPrevCPU
	s.mu.Lock()
	defer s.mu.Unlock()
	t1, i1, ok := readCPU(env)
	if !ok {
		return 0
	}
	if !s.have {
		s.total, s.idle, s.have = t1, i1, true
		nanosleep(200e6)
		t2, i2, ok := readCPU(env)
		if !ok {
			return 0
		}
		t1, i1 = t2, i2
	}
	dt, di := t1-s.total, i1-s.idle
	s.total, s.idle = t1, i1
	if dt == 0 || di > dt {
		return 0
	}
	return uint((dt - di) * 100 / dt)
}

// memoryPercent is web_get_memory_usage: (MemTotal-MemFree-Buffers-Cached)
// / MemTotal as double, narrowed to float, times 100.0f, printed "%.2f".
func memoryPercent(env *Env) string {
	var total, free, buffers, cached uint32
	if raw, ok := readFile(env, "/proc/meminfo", 64<<10); ok {
		for _, line := range fgetsLines(string(raw), 256) {
			var dst *uint32
			var format string
			switch {
			case strings.HasPrefix(line, "MemTotal:"):
				dst, format = &total, "MemTotal:"
			case strings.HasPrefix(line, "MemFree:"):
				dst, format = &free, "MemFree:"
			case strings.HasPrefix(line, "Buffers:"):
				dst, format = &buffers, "Buffers:"
			case strings.HasPrefix(line, "Cached:"):
				dst, format = &cached, "Cached:"
			default:
				continue
			}
			cemu.Sscanf(strings.TrimPrefix(line, format), "%s", func(_ int, v string) {
				n, _ := strconv.ParseUint(v, 10, 32)
				*dst = uint32(n)
			})
		}
	}
	if total == 0 {
		return "0.00"
	}
	used := total - free - buffers - cached
	ratio := float32(float64(used) / float64(total))
	pct := ratio * float32(100.0)
	return strconv.FormatFloat(float64(pct), 'f', 2, 64)
}

func nanosleep(ns int64) { sysx.Sleep(ns) }
