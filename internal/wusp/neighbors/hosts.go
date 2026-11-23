package neighbors

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// maxHostsEntries bounds how much of a hosts file is kept. A device with a
// pathological hosts file (an ad-blocking list with 100k lines) must not grow
// the agent's footprint for the sake of a neighbor's display name.
const maxHostsEntries = 4096

// ParseHostsFile reads an /etc/hosts-style file into an address-to-name map.
// This is the OS's own cached name for a host, not a lookup: the agent never
// resolves anything to fill Neighbor.{i}.HostName.
func ParseHostsFile(text string) map[string]string {
	out := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() && len(out) < maxHostsEntries {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}
		key := canonicalIP(ip)
		if key == "" {
			continue
		}
		// The first name on the line is the canonical one; a later line for
		// the same address does not override an earlier one, matching how a
		// resolver reads the file.
		if _, ok := out[key]; !ok {
			out[key] = fields[1]
		}
	}
	return out
}

// LoadHostsFile reads the platform's hosts file, returning an empty map when
// it cannot be read. Reading a file is passive; it sends nothing.
func LoadHostsFile(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	return ParseHostsFile(string(data))
}

// canonicalIP normalizes an address to the form used as a hosts-map key.
func canonicalIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// NameFor returns the hosts-file name for an address, if the file had one.
func NameFor(hosts map[string]string, ip net.IP) string {
	if len(hosts) == 0 {
		return ""
	}
	return hosts[canonicalIP(ip)]
}
