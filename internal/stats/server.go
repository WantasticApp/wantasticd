package stats

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"wantastic-agent/internal/device"
	"wantastic-agent/pkg/version"

	"golang.org/x/sys/cpu"
)

// Collector gathers device metrics for serialization and delivery over WireGuard.
// No HTTP server — metrics are collected on-demand by the WireGuard send path.
type Collector struct {
	device    *device.Device
	startTime time.Time
}

// Metrics represents comprehensive device metrics
type Metrics struct {
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	Platform  string    `json:"platform"`

	CPU struct {
		Cores int    `json:"cores"`
		Arch  string `json:"arch"`
		Usage string `json:"usage"`
	} `json:"cpu"`

	Memory struct {
		Allocated uint64 `json:"allocated"`
		Total     uint64 `json:"total"`
	} `json:"memory"`

	Network struct {
		Interfaces []InterfaceInfo `json:"interfaces"`
		Traffic    TrafficStats    `json:"traffic"`
	} `json:"network"`

	WiFi struct {
		Interfaces []WiFiInterfaceInfo `json:"interfaces"`
		Connected  bool                `json:"connected"`
		Signal     int                 `json:"signal"`
		Noise      int                 `json:"noise"`
		Bitrate    int                 `json:"bitrate"`
	} `json:"wifi"`

	WireGuard struct {
		Connected bool   `json:"connected"`
		PublicKey string `json:"public_key"`
		Peers     int    `json:"peers"`
	} `json:"wireguard"`

	Agent struct {
		Uptime  string `json:"uptime"`
		Version string `json:"version"`
		Status  string `json:"status"`
	} `json:"agent"`

	Modem *ModemInfo `json:"modem,omitempty"`
	GPS   *GPSInfo   `json:"gps,omitempty"`
	Mesh  *MeshInfo  `json:"mesh,omitempty"`
}

type InterfaceInfo struct {
	Name    string   `json:"name"`
	MAC     string   `json:"mac"`
	IPs     []string `json:"ips"`
	TxBytes uint64   `json:"tx_bytes"`
	RxBytes uint64   `json:"rx_bytes"`
	Up      bool     `json:"up"`
}

type NearbyNetwork struct {
	SSID     string `json:"ssid"`
	BSSID    string `json:"bssid"`
	Signal   int    `json:"signal"`
	Noise    int    `json:"noise"`
	Channel  int    `json:"channel"`
	Security string `json:"security"`
	PHYMode  string `json:"phy_mode"`
}

type WiFiInterfaceInfo struct {
	Name      string          `json:"name"`
	MAC       string          `json:"mac"`
	SSID      string          `json:"ssid"`
	Connected bool            `json:"connected"`
	Signal    int             `json:"signal"`
	Noise     int             `json:"noise"`
	Bitrate   int             `json:"bitrate"`
	Frequency int             `json:"frequency"`
	Channel   int             `json:"channel"`
	PHYMode   string          `json:"phy_mode"`
	Security  string          `json:"security"`
	SNR       int             `json:"snr"`
	MCSIndex  int             `json:"mcs_index"`
	TxPower   int             `json:"tx_power"`
	RxBytes   uint64          `json:"rx_bytes"`
	TxBytes   uint64          `json:"tx_bytes"`
	RxPackets uint64          `json:"rx_packets"`
	TxPackets uint64          `json:"tx_packets"`
	Nearby    []NearbyNetwork `json:"nearby"`
}

type TrafficStats struct {
	TotalTx uint64 `json:"total_tx"`
	TotalRx uint64 `json:"total_rx"`
	TxRate  uint64 `json:"tx_rate"`
	RxRate  uint64 `json:"rx_rate"`
}

type MeshInfo struct {
	Name     string    `json:"name,omitempty"`
	Protocol string    `json:"protocol"`
	Role     string    `json:"role"`
	IsCenter bool      `json:"is_center"`
	Topology *MeshNode `json:"topology,omitempty"`
}

type MeshNode struct {
	Name     string      `json:"name"`
	MAC      string      `json:"mac"`
	Backhaul string      `json:"backhaul,omitempty"`
	IP       string      `json:"ip,omitempty"`
	Signal   int         `json:"signal,omitempty"`
	Role     string      `json:"role,omitempty"`
	Children []*MeshNode `json:"children,omitempty"`
}

type ModemInfo struct {
	Model        string `json:"model"`
	IMEI         string `json:"imei"`
	IMSI         string `json:"imsi"`
	PhoneNumber  string `json:"phone_number"`
	SIMSlot      string `json:"sim_slot"`
	Signal       int    `json:"signal"`
	Registration string `json:"registration"`
	Operator     string `json:"operator"`
	Tech         string `json:"tech"`
}

type GPSInfo struct {
	Lat        float64   `json:"lat"`
	Lon        float64   `json:"lon"`
	Alt        float64   `json:"alt"`
	Speed      float64   `json:"speed"`
	Satellites int       `json:"satellites"`
	Fix        string    `json:"fix"`
	Timestamp  time.Time `json:"timestamp"`
}

// NewCollector creates a new metrics collector.
func NewCollector(device *device.Device) *Collector {
	return &Collector{
		device:    device,
		startTime: time.Now(),
	}
}

// Backward compat aliases — agent.go used stats.NewServer / stats.Server
type Server = Collector

func NewServer(device *device.Device, _ string) *Server {
	return NewCollector(device)
}
func (c *Collector) Start() error { return nil }
func (c *Collector) Stop()        {}

// GetSerializedMetrics is defined in serializer.go

func (c *Collector) collectMetrics() Metrics {
	var m Metrics
	m.Timestamp = time.Now()
	m.Hostname, _ = os.Hostname()
	m.Platform = runtime.GOOS

	m.CPU.Cores = runtime.NumCPU()
	m.CPU.Arch = runtime.GOARCH
	m.CPU.Usage = collectCPUUsage()

	used, total := collectSystemMemory()
	m.Memory.Allocated = used
	m.Memory.Total = total

	var totalTx, totalRx uint64
	m.Network.Interfaces, totalTx, totalRx = collectNetworkInterfaceStatistics()
	m.Network.Traffic.TotalTx = totalTx
	m.Network.Traffic.TotalRx = totalRx

	wifiInterfaces, wifiConnected := collectWiFiStatistics()
	m.WiFi.Interfaces = wifiInterfaces
	m.WiFi.Connected = wifiConnected

	if len(wifiInterfaces) > 0 {
		var totalSignal, totalBitrate int
		for _, iface := range wifiInterfaces {
			totalSignal += iface.Signal
			totalBitrate += iface.Bitrate
		}
		m.WiFi.Signal = totalSignal / len(wifiInterfaces)
		m.WiFi.Bitrate = totalBitrate / len(wifiInterfaces)
	}

	m.WireGuard.Connected = c.device.HasActiveHandshake()
	m.WireGuard.PublicKey = c.device.GetPublicKey()

	m.Agent.Uptime = formatUptimeDuration(getHostUptime())
	m.Agent.Version = version.Version
	m.Agent.Status = "running"

	m.Mesh = collectMeshStatistics()
	m.Modem = collectModemStatistics()
	m.GPS = collectGPSStatistics()

	return m
}

func formatUptimeDuration(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

func getInterfaceIPs(ifaceName string) []string {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	var ips []string
	for _, addr := range addrs {
		ips = append(ips, addr.String())
	}
	return ips
}

func getCPUInfo() string {
	if cpu.X86.HasAVX2 {
		return "x86_64 (AVX2)"
	}
	return runtime.GOARCH
}
