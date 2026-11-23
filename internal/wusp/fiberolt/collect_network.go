package fiberolt

import (
	"context"
	"log"
	"strconv"
	"strings"

	"wantastic-agent/internal/wusp"
)

const oltNetPrefix = wusp.WUSPOLTPrefix + "Network."

// CollectOLTNetwork fills Device.WUSP_OLT.Network.* from verified FOS
// webserver goform endpoints: getLanIpMask, getSystemTimeInfo, getAclList,
// getStaticRouteList, getIPv4RoutingTable.
func CollectOLTNetwork(ctx context.Context, api *Client, msg *wusp.Message) {
	collectOLTMgmtInterface(ctx, api, msg)
	collectOLTNetworkConfig(ctx, api, msg)
	collectOLTACL(ctx, api, msg)
	collectOLTRoutes(ctx, api, msg)
	collectOLTServicePorts(ctx, api, msg)
	collectOLTQVLANs(ctx, api, msg)
}

// ---- Management interface -------------------------------------------------

func collectOLTMgmtInterface(ctx context.Context, api *Client, msg *wusp.Message) {
	var out struct {
		IP   string `json:"ip"`
		Mask string `json:"mask"`
	}
	if err := api.post(ctx, "/goform/getLanIpMask", map[string]any{}, &out); err != nil {
		log.Printf("[OLT] network mgmt: %v", err)
		return
	}
	msg.Set(oltNetPrefix+"Mgmt.IPAddress", wusp.String(out.IP))
	msg.Set(oltNetPrefix+"Mgmt.SubnetMask", wusp.String(out.Mask))

	var misc struct {
		Gateway string `json:"gateway"`
		MAC     string `json:"mac"`
		Status  string `json:"status"`
	}
	if err := api.post(ctx, "/goform/getSysMisc", map[string]any{}, &misc); err == nil {
		if misc.Gateway != "" {
			msg.Set(oltNetPrefix+"Mgmt.Gateway", wusp.String(misc.Gateway))
		}
		if misc.MAC != "" {
			msg.Set(oltNetPrefix+"Mgmt.MACAddress", wusp.String(misc.MAC))
		}
		if misc.Status != "" {
			msg.Set(oltNetPrefix+"Mgmt.Status", wusp.String(misc.Status))
		}
	}
}

// ---- Network config (DNS, NTP) -------------------------------------------

func collectOLTNetworkConfig(ctx context.Context, api *Client, msg *wusp.Message) {
	var out struct {
		NTPServer  string `json:"ntpServer"`
		NTPSync    string `json:"ntpSync"`
		NTPEnable  string `json:"ntpEnable"`
		Timezone   string `json:"timezone"`
		DNSServer1 string `json:"dnsServer1"`
		DNSServer2 string `json:"dnsServer2"`
	}
	if err := api.post(ctx, "/goform/getSystemTimeInfo", map[string]any{}, &out); err != nil {
		log.Printf("[OLT] network time: %v", err)
		return
	}
	idx := 1
	if out.DNSServer1 != "" {
		msg.Set(oltNetPrefix+"DNS.Server."+strconv.Itoa(idx)+".Address", wusp.String(out.DNSServer1))
		idx++
	}
	if out.DNSServer2 != "" {
		msg.Set(oltNetPrefix+"DNS.Server."+strconv.Itoa(idx)+".Address", wusp.String(out.DNSServer2))
		idx++
	}
	msg.Set(oltNetPrefix+"DNS.ServerNumberOfEntries", wusp.Uint(uint64(idx-1)))
	if out.NTPServer != "" {
		msg.Set(oltNetPrefix+"NTP.Server", wusp.String(out.NTPServer))
		msg.Set(oltNetPrefix+"NTP.Enabled", wusp.Bool(out.NTPEnable == "1" || out.NTPSync == "1" || strings.EqualFold(out.NTPEnable, "true")))
	}
}

// ---- ACL / firewall rules ------------------------------------------------

func collectOLTACL(ctx context.Context, api *Client, msg *wusp.Message) {
	var out struct {
		List []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Type     string `json:"type"`
			Action   string `json:"action"`
			Protocol string `json:"protocol"`
			SrcIP    string `json:"srcIp"`
			DstIP    string `json:"dstIp"`
			SrcPort  string `json:"srcPort"`
			DstPort  string `json:"dstPort"`
			Status   string `json:"status"`
		} `json:"list"`
	}
	if err := api.post(ctx, "/goform/getAclList", map[string]any{}, &out); err != nil {
		log.Printf("[OLT] acl list: %v", err)
		return
	}
	for i, rule := range out.List {
		row := oltNetPrefix + "ACL." + strconv.Itoa(i+1) + "."
		msg.Set(row+"ID", wusp.String(rule.ID))
		msg.Set(row+"Name", wusp.String(rule.Name))
		msg.Set(row+"Type", wusp.String(rule.Type))
		msg.Set(row+"Action", wusp.String(rule.Action))
		msg.Set(row+"Protocol", wusp.String(rule.Protocol))
		msg.Set(row+"SrcIP", wusp.String(rule.SrcIP))
		msg.Set(row+"DstIP", wusp.String(rule.DstIP))
		msg.Set(row+"SrcPort", wusp.String(rule.SrcPort))
		msg.Set(row+"DstPort", wusp.String(rule.DstPort))
		msg.Set(row+"Status", wusp.String(rule.Status))
	}
	msg.Set(oltNetPrefix+"ACLNumberOfEntries", wusp.Uint(uint64(len(out.List))))
}

// ---- Static routes -------------------------------------------------------

func collectOLTRoutes(ctx context.Context, api *Client, msg *wusp.Message) {
	var out struct {
		List []struct {
			Destination string `json:"destination"`
			Mask        string `json:"mask"`
			Gateway     string `json:"gateway"`
			Interface   string `json:"interface"`
			Metric      string `json:"metric"`
		} `json:"list"`
	}
	if err := api.post(ctx, "/goform/getStaticRouteList", map[string]any{}, &out); err != nil {
		log.Printf("[OLT] route list: %v", err)
		return
	}
	for i, r := range out.List {
		row := oltNetPrefix + "Route." + strconv.Itoa(i+1) + "."
		msg.Set(row+"Destination", wusp.String(r.Destination))
		msg.Set(row+"Mask", wusp.String(r.Mask))
		msg.Set(row+"Gateway", wusp.String(r.Gateway))
		msg.Set(row+"Interface", wusp.String(r.Interface))
		if metric, err := strconv.ParseUint(r.Metric, 10, 64); err == nil {
			msg.Set(row+"Metric", wusp.Uint(metric))
		}
	}
	msg.Set(oltNetPrefix+"RouteNumberOfEntries", wusp.Uint(uint64(len(out.List))))
}

// ---- Service ports (ONU-to-VLAN mapping, e.g. VLAN4000) ------------------

func collectOLTServicePorts(ctx context.Context, api *Client, msg *wusp.Message) {
	var out struct {
		List []struct {
			PONPort  string `json:"ponPort"`
			OnuID    string `json:"onuId"`
			GEMPort  string `json:"gemport"`
			SVLAN    string `json:"svlan"`
			CVLAN    string `json:"cvlan"`
			VLANMode string `json:"vlanmode"`
		} `json:"list"`
	}
	if err := api.post(ctx, "/goform/getServicePort", map[string]any{}, &out); err != nil {
		log.Printf("[OLT] service port list: %v", err)
		return
	}
	for i, sp := range out.List {
		row := oltNetPrefix + "ServicePort." + strconv.Itoa(i+1) + "."
		msg.Set(row+"PONPort", wusp.String(sp.PONPort))
		msg.Set(row+"OnuID", wusp.String(sp.OnuID))
		msg.Set(row+"GEMPort", wusp.String(sp.GEMPort))
		msg.Set(row+"SVLAN", wusp.String(sp.SVLAN))
		msg.Set(row+"CVLAN", wusp.String(sp.CVLAN))
		msg.Set(row+"VLANMode", wusp.String(sp.VLANMode))
	}
	msg.Set(oltNetPrefix+"ServicePortNumberOfEntries", wusp.Uint(uint64(len(out.List))))
}

// ---- Q-VLANs (802.1Q VLAN database) -------------------------------------

func collectOLTQVLANs(ctx context.Context, api *Client, msg *wusp.Message) {
	var out struct {
		List []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			StartVLAN string `json:"startvlan"`
			EndVLAN   string `json:"endvlan"`
			Enabled   string `json:"vlanEn"`
		} `json:"list"`
	}
	if err := api.post(ctx, "/goform/getQvlanList", map[string]any{}, &out); err != nil {
		log.Printf("[OLT] qvlan list: %v", err)
		return
	}
	for i, v := range out.List {
		row := oltNetPrefix + "QVLAN." + strconv.Itoa(i+1) + "."
		msg.Set(row+"ID", wusp.String(v.ID))
		msg.Set(row+"Name", wusp.String(v.Name))
		msg.Set(row+"StartVLAN", wusp.String(v.StartVLAN))
		msg.Set(row+"EndVLAN", wusp.String(v.EndVLAN))
		msg.Set(row+"Enabled", wusp.Bool(v.Enabled == "1" || strings.EqualFold(v.Enabled, "true")))
	}
	msg.Set(oltNetPrefix+"QVLANNumberOfEntries", wusp.Uint(uint64(len(out.List))))
}
