package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/config"
	"wantastic-agent/internal/device"
	"wantastic-agent/internal/wusp/platforms"
)

// Tunnel is implemented by the app's VpnService: it builds the interface
// Wantastic asks for (addresses, routes, DNS as comma-separated lists) and
// returns its file descriptor, which the engine then owns.
type Tunnel interface {
	Open(mtu int, addresses, routes, dns string) (int, error)
	// DefaultRoute asks for the internet (0.0.0.0/0) to go into the tunnel,
	// or no longer: an exit node started or stopped carrying it.
	DefaultRoute(on bool)
}

var (
	mu     sync.Mutex
	runner *agent.Agent
	cancel context.CancelFunc
)

// Start runs the agent with this phone's config (agent JSON, from
// ConfigFromClaim), on the tunnel the app provides. It returns once the
// tunnel is up; the agent keeps running until Stop.
func Start(configJSON string, tun Tunnel) error {
	if tun == nil {
		return errors.New("no tunnel provider")
	}
	var cfg config.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return err
	}
	// The app owns updates and the interface; the phone shares no LAN.
	cfg.AutoUpdate = false
	cfg.AllowLocalAccess = false
	cfg.Interface.TUNMode = true

	mu.Lock()
	defer mu.Unlock()
	if runner != nil {
		return errors.New("already running")
	}
	device.ExternalTUN = func(req device.TUNRequest) (int, error) {
		return tun.Open(req.MTU, join(req.Addresses), join(req.Routes), strings.Join(req.DNS, ","))
	}
	device.ExternalDefaultRoute = tun.DefaultRoute
	a, err := agent.New(&cfg)
	if err != nil {
		return err
	}
	ctx, stop := context.WithCancel(context.Background())
	if err := a.Start(ctx); err != nil {
		stop()
		_ = a.Stop()
		return err
	}
	runner, cancel = a, stop
	return nil
}

// Stop ends the agent and closes the tunnel.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if runner == nil {
		return
	}
	cancel()
	_ = runner.Stop()
	runner, cancel = nil, nil
}

// Running reports whether the agent is up.
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return runner != nil && runner.IsRunning()
}

// API calls the agent's local API in-process (status, exit node, ping): the
// same endpoints the desktop tray uses, without a port other apps could reach.
func API(method, path, body string) (string, error) {
	mu.Lock()
	a := runner
	mu.Unlock()
	if a == nil {
		return "", errors.New("not running")
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	// The app is the local controller (the header the tray sends).
	req.Header.Set(agent.ControlHeader, "1")
	rec := httptest.NewRecorder()
	a.LocalAPI().ServeHTTP(rec, req)
	if rec.Code >= http.StatusBadRequest {
		return "", errors.New(strings.TrimSpace(rec.Body.String()))
	}
	return rec.Body.String(), nil
}

func join[T interface{ String() string }](items []T) string {
	parts := make([]string, len(items))
	for i, p := range items {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

// SetDeviceInfo takes the app's reading of the phone (model, Android version,
// memory, Wi-Fi...) as JSON, for the console's WUSP view: an app cannot read
// the system files and sockets the Linux collectors use.
func SetDeviceInfo(reading string) error {
	return platforms.SetAndroidSnapshot([]byte(reading))
}

// SocketFDs lists WireGuard's UDP sockets (comma-separated) for the app to
// protect, so the tunnel's own packets never go back into the tunnel.
func SocketFDs() string {
	mu.Lock()
	a := runner
	mu.Unlock()
	if a == nil {
		return ""
	}
	fds := a.SocketFDs()
	parts := make([]string, len(fds))
	for i, fd := range fds {
		parts[i] = strconv.Itoa(fd)
	}
	return strings.Join(parts, ",")
}
