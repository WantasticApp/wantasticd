package fiberolt

// Safety guards: writes that would cut the agent off from the OLT it
// manages (its -olt-url route) are refused with a clear error before
// anything is posted. Guards are named on a Setter (Guard) or an OLTWrite
// spec and run against the final request body.

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"wantastic-agent/internal/wusp"
)

// ErrGuarded marks a write refused by a safety guard.
var ErrGuarded = fmt.Errorf("olt: refused by safety guard")

func guardErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrGuarded}, args...)...)
}

// target is how the agent reaches the OLT web API.
type target struct {
	scheme, host string
	port         int
}

func (c *Client) target() target {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return target{}
	}
	t := target{scheme: u.Scheme, host: u.Hostname()}
	if p, err := strconv.Atoi(u.Port()); err == nil {
		t.port = p
	} else if t.scheme == "https" {
		t.port = 443
	} else {
		t.port = 80
	}
	return t
}

// guards maps a guard name to its check. body is the request about to be
// posted; row is the current table row / form (may be nil).
var guards = map[string]func(ctx context.Context, env *Env, body map[string]any, row Doc) error{
	"mgmtAddress":  guardMgmtAddress,
	"servicePorts": guardServicePorts,
	"loginManage":  guardLoginManage,
	"vlanL3":       guardVLANL3,
	"vlanDelete":   guardVLANDeleteRows,
	"portStatus":   guardPortStatus,
	"vlanMember":   guardVLANMember,
	"profileBind":  guardProfileBind,
}

// guardProfileBind refuses deleting a profile whose Bind count (ONTs
// referencing it) is above 0; the rows are the {list:[...]} of the delete.
func guardProfileBind(_ context.Context, _ *Env, body map[string]any, _ Doc) error {
	list, _ := body["list"].([]any)
	for _, it := range list {
		row, _ := it.(map[string]any)
		if row == nil {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(Str(row["bind"]))); err == nil && n > 0 {
			return guardErr("profile %s is bound to %d ONT(s); unbind them before deleting it", Str(row["profileid"]), n)
		}
	}
	return nil
}

// GuardNames lists the guards page specs may reference.
func GuardNames() []string {
	out := make([]string, 0, len(guards))
	for k := range guards {
		out = append(out, k)
	}
	return out
}

func runGuard(ctx context.Context, env *Env, name, endpoint string, body map[string]any, row Doc) error {
	if name == "" {
		return nil
	}
	g, ok := guards[name]
	if !ok {
		return fmt.Errorf("olt: unknown guard %q on %s", name, endpoint)
	}
	return g(ctx, env, body, row)
}

// guardMgmtAddress: setDeviceInfo must not move the management address
// the agent talks to (ip/mask/ipType, or the in-band address, mask and
// management VLAN when the agent uses the in-band address, or the gateway).
func guardMgmtAddress(ctx context.Context, env *Env, body map[string]any, _ Doc) error {
	cur, _ := body["originData"].(map[string]any)
	if cur == nil {
		doc, err := newCycle(ctx, env).Doc("sysStatus")
		if err != nil {
			return err
		}
		cur = doc
	}
	host := env.API.target().host
	changed := func(keys ...string) []string {
		var out []string
		for _, k := range keys {
			if nv, ok := body[k]; ok && Str(nv) != Str(cur[k]) {
				out = append(out, k)
			}
		}
		return out
	}
	if host != "" && host == Str(cur["ip"]) {
		if c := changed("ip", "mask", "ipType", "gateway"); len(c) > 0 {
			return guardErr("the agent reaches the OLT at %s (management address); changing %s would cut it off. Change it from the OLT web UI or point -olt-url at another address first", host, strings.Join(c, ", "))
		}
	}
	if host != "" && host == Str(cur["inbandip"]) {
		if c := changed("inbandip", "inbandmask", "mngvlan", "gateway"); len(c) > 0 {
			return guardErr("the agent reaches the OLT at %s (in-band address); changing %s would cut it off", host, strings.Join(c, ", "))
		}
	}
	return nil
}

// guardServicePorts: setServicePort must keep the web port the agent uses.
func guardServicePorts(ctx context.Context, env *Env, body map[string]any, row Doc) error {
	t := env.API.target()
	key := "httpport"
	if t.scheme == "https" {
		key = "httpsport"
	}
	nv, ok := body[key]
	if !ok {
		return nil
	}
	cur := row
	if cur == nil {
		doc, err := fetchPage(ctx, env.API, "/goform/getServicePort", nil, nil)
		if err != nil {
			return err
		}
		cur, _ = doc.(Doc)
	}
	if Str(nv) != Str(cur[key]) {
		return guardErr("the agent reaches the OLT web server over %s (port %d); changing %s from %s to %s would cut it off", t.scheme, t.port, key, Str(cur[key]), Str(nv))
	}
	return nil
}

// guardLoginManage: setVerifyCode must keep the web service the agent uses.
func guardLoginManage(_ context.Context, env *Env, body map[string]any, _ Doc) error {
	key := "httpEn"
	if env.API.target().scheme == "https" {
		key = "httpsEn"
	}
	if v, ok := body[key]; ok && !truthy(v) {
		return guardErr("the agent manages the OLT over %s; disabling %s would cut it off", env.API.target().scheme, key)
	}
	return nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	default:
		s := strings.ToLower(Str(v))
		return s == "1" || s == "true" || s == "enable" || s == "on"
	}
}

// agentVLANs returns the VLANs the agent's route depends on: VLAN 1, the
// management VLAN of the device info, and the VLAN whose L3 interface
// address is the -olt-url host.
func agentVLANs(ctx context.Context, env *Env) map[string]string {
	out := map[string]string{"1": "the default VLAN"}
	c := newCycle(ctx, env)
	host := env.API.target().host
	if doc, err := c.Doc("sysStatus"); err == nil {
		if v := Str(doc["mngvlan"]); v != "" && v != "0" {
			out[v] = "the management VLAN"
		}
	}
	if raw, err := c.Source("qvlans"); err == nil {
		for _, row := range ListRows(raw, "list") {
			if host != "" && Str(row["ip"]) == host {
				out[Str(row["vlanId"])] = "the VLAN whose interface " + host + " the agent uses"
			}
		}
	}
	return out
}

// guardVLANDelete refuses deleting a VLAN the agent depends on.
func guardVLANDelete(ctx context.Context, env *Env, vlanID string) error {
	if why, ok := agentVLANs(ctx, env)[strings.TrimSpace(vlanID)]; ok {
		return guardErr("VLAN %s is %s; deleting it would cut the agent off", vlanID, why)
	}
	return nil
}

func guardVLANDeleteRows(ctx context.Context, env *Env, body map[string]any, row Doc) error {
	if row != nil {
		return guardVLANDelete(ctx, env, Str(row["vlanId"]))
	}
	return nil
}

// guardVLANL3: editing the VLAN interface the agent uses must keep its
// L3 interface and address.
func guardVLANL3(ctx context.Context, env *Env, body map[string]any, row Doc) error {
	host := env.API.target().host
	if row == nil || host == "" || Str(row["ip"]) != host {
		return nil
	}
	if v, ok := body["threeLayersEn"]; ok && Str(v) != "1" {
		return guardErr("VLAN %s carries the address %s the agent uses; disabling its L3 interface would cut it off", Str(row["vlanId"]), host)
	}
	for _, k := range []string{"staticIp", "mask", "ipType"} {
		cur := row[k]
		if k == "staticIp" {
			cur = row["ip"]
		}
		if v, ok := body[k]; ok && Str(v) != Str(cur) {
			return guardErr("VLAN %s carries the address %s the agent uses; changing %s would cut it off", Str(row["vlanId"]), host, k)
		}
	}
	return nil
}

// uplinkUp reports whether a port name is an uplink (ge/xge) with link up.
func uplinkUp(ctx context.Context, env *Env, port string) bool {
	if !strings.HasPrefix(port, "ge") && !strings.HasPrefix(port, "xge") {
		return false
	}
	raw, err := newCycle(ctx, env).Source("sysStatus")
	if err != nil {
		return true // unknown: be safe
	}
	for _, p := range ListRows(raw, "port") {
		if Str(p["portName"]) == port {
			return Str(p["portStatus"]) == "1"
		}
	}
	return false
}

// bodyPorts returns the port names a port-page body targets.
func bodyPorts(body map[string]any, row Doc) []string {
	var out []string
	switch v := body["port"].(type) {
	case []any:
		for _, p := range v {
			out = append(out, Str(p))
		}
	case []string:
		out = append(out, v...)
	case string:
		out = append(out, v)
	}
	if len(out) == 0 && row != nil {
		out = append(out, Str(row["portName"]))
	}
	return out
}

// guardPortStatus: shutting down (portStatus "0") a link-up uplink port is
// refused: the agent may reach the OLT through it.
func guardPortStatus(ctx context.Context, env *Env, body map[string]any, row Doc) error {
	if v, ok := body["portStatus"]; !ok || Str(v) != "0" {
		return nil
	}
	for _, p := range bodyPorts(body, row) {
		if uplinkUp(ctx, env, p) {
			return guardErr("%s is a link-up uplink the agent may reach the OLT through; shut it down from the OLT web UI or console if you are sure", p)
		}
	}
	return nil
}

// vlanListHas reports whether a vendor VLAN list ("1,10-20,4000", "--")
// contains vid.
func vlanListHas(list string, vid int) bool {
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "--" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		lo, err1 := strconv.Atoi(strings.TrimSpace(a))
		hi := lo
		var err2 error
		if isRange {
			hi, err2 = strconv.Atoi(strings.TrimSpace(b))
		}
		if err1 == nil && err2 == nil && vid >= lo && vid <= hi {
			return true
		}
	}
	return false
}

// guardVLANMember: a link-up uplink must keep carrying the VLAN the agent
// reaches the OLT through (as PVID, tagged or untagged member).
func guardVLANMember(ctx context.Context, env *Env, body map[string]any, row Doc) error {
	vlans := agentVLANs(ctx, env)
	delete(vlans, "1")
	if len(vlans) == 0 {
		return nil
	}
	for _, p := range bodyPorts(body, row) {
		if !uplinkUp(ctx, env, p) {
			continue
		}
		for v := range vlans {
			vid, err := strconv.Atoi(v)
			if err != nil {
				continue
			}
			field := func(k string) string {
				if x, ok := body[k]; ok {
					return Str(x)
				}
				if row != nil {
					return Str(row[k])
				}
				return ""
			}
			was := field("pvid") == v || (row != nil && (vlanListHas(Str(row["tagged"]), vid) || vlanListHas(Str(row["untagged"]), vid) || Str(row["pvid"]) == v))
			now := field("pvid") == v || vlanListHas(field("tagged"), vid) || vlanListHas(field("untagged"), vid)
			if was && !now {
				return guardErr("uplink %s carries VLAN %s (%s); removing it would cut the agent off", p, v, vlans[v])
			}
		}
	}
	return nil
}

// sameHost reports whether two host strings name the same address.
func sameHost(a, b string) bool {
	if a == b {
		return true
	}
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	return ia != nil && ib != nil && ia.Equal(ib)
}

var _ = sameHost
var _ = wusp.ErrUSPPathUnsupported
