package fiberolt

import (
	"context"
	"fmt"
	"strings"

	"wantastic-agent/internal/wusp"
)

// SetOLTNetworkParam handles Device.WUSP_OLT.Network.* setters using verified
// FOS webserver goform endpoints: setStaticRouteInfo, setAclListInfo,
// setSystemTimeInfo.
func SetOLTNetworkParam(ctx context.Context, api *Client, path string, value wusp.Value) error {
	const prefix = wusp.WUSPOLTPrefix + "Network."
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}

	switch rest {
	case "Mgmt.IPAddress":
		return api.SetLanIP(ctx, "ip", wusp.ValueToString(value))
	case "Mgmt.SubnetMask":
		return api.SetLanIP(ctx, "mask", wusp.ValueToString(value))
	case "DNS.Server.1.Address":
		return api.SetSystemTime(ctx, "dnsServer1", wusp.ValueToString(value))
	case "DNS.Server.2.Address":
		return api.SetSystemTime(ctx, "dnsServer2", wusp.ValueToString(value))
	case "NTP.Server":
		return api.SetSystemTime(ctx, "ntpServer", wusp.ValueToString(value))
	case "NTP.Enabled":
		v := "0"
		if value.AsBool() {
			v = "1"
		}
		return api.SetSystemTime(ctx, "ntpEnable", v)
	}
	return wusp.ErrUSPPathUnsupported
}

// OLTNetworkOperate runs Device.WUSP_OLT.Network.* Operate commands.
func OLTNetworkOperate(ctx context.Context, api *Client, cmd string, input *wusp.Message) error {
	const prefix = wusp.WUSPOLTPrefix + "Network."
	rest, ok := strings.CutPrefix(cmd, prefix)
	if !ok {
		return wusp.ErrUSPPathUnsupported
	}

	switch rest {
	case "ACL.Add()":
		return addOLTACL(ctx, api, input)
	case "ACL.Delete()":
		return deleteOLTACL(ctx, api, input)
	case "Route.Add()":
		return addOLTRoute(ctx, api, input)
	case "Route.Delete()":
		return deleteOLTRoute(ctx, api, input)
	case "ServicePort.Add()":
		return addOLTServicePort(ctx, api, input)
	case "ServicePort.Delete()":
		return deleteOLTServicePort(ctx, api, input)
	case "QVLAN.Add()":
		return addOLTQVLAN(ctx, api, input)
	case "QVLAN.Delete()":
		return deleteOLTQVLAN(ctx, api, input)
	case "BackupNetworkConfig()":
		return backupOLTNetworkConfig(ctx, api, input)
	}
	return wusp.ErrUSPPathUnsupported
}

// ---- ACL operations -------------------------------------------------------

func addOLTACL(ctx context.Context, api *Client, input *wusp.Message) error {
	name := OperateInputString(input, "Name")
	action := OperateInputString(input, "Action")
	protocol := OperateInputString(input, "Protocol")
	srcIP := OperateInputString(input, "SrcIP")
	dstIP := OperateInputString(input, "DstIP")
	srcPort := OperateInputString(input, "SrcPort")
	dstPort := OperateInputString(input, "DstPort")
	if name == "" {
		return fmt.Errorf("olt: ACL.Add() requires a Name input")
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.post(ctx, "/goform/setAclListInfo", map[string]any{
		"name": name, "action": action, "protocol": protocol,
		"srcIp": srcIP, "dstIp": dstIP, "srcPort": srcPort, "dstPort": dstPort,
	}, nil)
}

func deleteOLTACL(ctx context.Context, api *Client, input *wusp.Message) error {
	id := OperateInputString(input, "ID")
	if id == "" {
		return fmt.Errorf("olt: ACL.Delete() requires an ID input")
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.post(ctx, "/goform/delAclList", map[string]any{"id": id}, nil)
}

// ---- Route operations -----------------------------------------------------

func addOLTRoute(ctx context.Context, api *Client, input *wusp.Message) error {
	dest := OperateInputString(input, "Destination")
	mask := OperateInputString(input, "Mask")
	gw := OperateInputString(input, "Gateway")
	iface := OperateInputString(input, "Interface")
	if dest == "" {
		return fmt.Errorf("olt: Route.Add() requires a Destination input")
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.post(ctx, "/goform/setStaticRouteInfo", map[string]any{
		"destination": dest, "mask": mask, "gateway": gw, "interface": iface,
	}, nil)
}

func deleteOLTRoute(ctx context.Context, api *Client, input *wusp.Message) error {
	dest := OperateInputString(input, "Destination")
	if dest == "" {
		return fmt.Errorf("olt: Route.Delete() requires a Destination input")
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.post(ctx, "/goform/delStaticRouteList", map[string]any{"destination": dest}, nil)
}

// ---- Service port operations (ONU-to-VLAN mapping, e.g. VLAN4000) --------

func addOLTServicePort(ctx context.Context, api *Client, input *wusp.Message) error {
	ponPort := OperateInputString(input, "PONPort")
	onuID := OperateInputString(input, "OnuID")
	gemPort := OperateInputString(input, "GEMPort")
	svlan := OperateInputString(input, "SVLAN")
	cvlan := OperateInputString(input, "CVLAN")
	vlanMode := OperateInputString(input, "VLANMode")
	if ponPort == "" || onuID == "" {
		return fmt.Errorf("olt: ServicePort.Add() requires PONPort and OnuID inputs")
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.post(ctx, "/goform/setServicePort", map[string]any{
		"ponPort": ponPort, "onuId": onuID, "gemport": gemPort,
		"svlan": svlan, "cvlan": cvlan, "vlanmode": vlanMode,
	}, nil)
}

func deleteOLTServicePort(ctx context.Context, api *Client, input *wusp.Message) error {
	ponPort := OperateInputString(input, "PONPort")
	onuID := OperateInputString(input, "OnuID")
	if ponPort == "" || onuID == "" {
		return fmt.Errorf("olt: ServicePort.Delete() requires PONPort and OnuID inputs")
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.post(ctx, "/goform/delPortOnu", map[string]any{
		"ponPort": ponPort, "onuId": onuID,
	}, nil)
}

// ---- Q-VLAN operations ---------------------------------------------------

func addOLTQVLAN(ctx context.Context, api *Client, input *wusp.Message) error {
	startVLAN := OperateInputString(input, "StartVLAN")
	endVLAN := OperateInputString(input, "EndVLAN")
	if startVLAN == "" {
		return fmt.Errorf("olt: QVLAN.Add() requires a StartVLAN input")
	}
	if endVLAN == "" {
		endVLAN = startVLAN
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.post(ctx, "/goform/setQvlanInfo", map[string]any{
		"startvlan": startVLAN, "endvlan": endVLAN, "vlanEn": "1",
	}, nil)
}

func deleteOLTQVLAN(ctx context.Context, api *Client, input *wusp.Message) error {
	id := OperateInputString(input, "ID")
	if id == "" {
		return fmt.Errorf("olt: QVLAN.Delete() requires an ID input")
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.post(ctx, "/goform/delQvlanList", map[string]any{"id": id}, nil)
}

// ---- Network config backup ------------------------------------------------

func backupOLTNetworkConfig(ctx context.Context, api *Client, input *wusp.Message) error {
	config, err := api.DownloadConfig(ctx)
	if err != nil {
		return fmt.Errorf("olt: backup network config: %w", err)
	}
	if input != nil {
		input.Set(wusp.WUSPOLTPrefix+"Network.Config", wusp.String(config))
	}
	return nil
}

// ---- Client helpers for network settings ----------------------------------

// SetLanIP sets the management LAN IP/mask via goform/setQuickCfgNetwork.
func (c *Client) SetLanIP(ctx context.Context, field, value string) error {
	if err := c.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return c.post(ctx, "/goform/setQuickCfgNetwork", map[string]any{field: value}, nil)
}

// SetSystemTime sets DNS/NTP fields via goform/setSystemTimeInfo.
func (c *Client) SetSystemTime(ctx context.Context, field, value string) error {
	if err := c.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return c.post(ctx, "/goform/setSystemTimeInfo", map[string]any{field: value}, nil)
}
