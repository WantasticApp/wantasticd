//go:build windows

package dns

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Windows: DNS of the adapter with the lowest-metric default route, through
// the DnsClient PowerShell module (applies immediately).

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func powershell(ctx context.Context, script string) (string, error) {
	return runCommand(ctx, "", "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
}

func defaultIfIndex(ctx context.Context) (int, error) {
	out, err := powershell(ctx, "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property RouteMetric | Select-Object -First 1).ifIndex")
	if err != nil {
		return 0, err
	}
	index, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || index <= 0 {
		return 0, fmt.Errorf("no default route adapter")
	}
	return index, nil
}

func ReadControl(ctx context.Context) ControlState {
	if st, err := nativeReadControl(); err == nil {
		return st
	}
	index, err := defaultIfIndex(ctx)
	if err != nil {
		return ControlState{Method: "windows-dnsclient", Reason: err.Error()}
	}
	st := ControlState{Supported: true, Method: "windows-dnsclient"}
	eff, _ := powershell(ctx, fmt.Sprintf("(Get-DnsClientServerAddress -InterfaceIndex %d).ServerAddresses", index))
	st.Effective = strings.Fields(eff)
	static, _ := powershell(ctx, fmt.Sprintf("$g=(Get-NetAdapter -InterfaceIndex %d).InterfaceGuid; (Get-ItemProperty -Path ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\'+$g)).NameServer", index))
	if servers := strings.FieldsFunc(strings.TrimSpace(static), func(r rune) bool { return r == ',' || r == ' ' }); len(servers) > 0 {
		st.Manual, st.Servers = true, servers
	}
	return st
}

func SetServers(ctx context.Context, servers []string) error {
	servers, err := NormalizeServers(servers)
	if err != nil {
		return err
	}
	if err := nativeSetServers(servers); !errors.Is(err, errNativeUnavailable) {
		return err
	}
	index, err := defaultIfIndex(ctx)
	if err != nil {
		return err
	}
	if len(servers) == 0 {
		_, err = powershell(ctx, fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ResetServerAddresses", index))
		return err
	}
	quoted := make([]string, len(servers))
	for i, s := range servers {
		quoted[i] = psQuote(s)
	}
	_, err = powershell(ctx, fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %d -ServerAddresses @(%s)", index, strings.Join(quoted, ",")))
	return err
}
