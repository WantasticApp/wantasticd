package endpoints

import (
	"errors"
	"strconv"
	"strings"

	"wantastic-agent/internal/oltd/cemu"
	"wantastic-agent/internal/oltd/sysx"
	"wantastic-agent/internal/oltd/wire"
)

// Hand ports of vendor setters that build their request by hand (see
// ports_getters.go for the conventions). Two request layouts occur:
//
//   - "legacy": the parameter lengths as u16 at +34, +36, ... and the
//     strings packed from +58, NUL separated (sprintf + strlen chain);
//     the reply is formatted by setCmdResultWebService (plainReply) and
//     "0..." becomes {"errCode":"0"}.
//   - "quick": formQuickParamToBuf's layout written by hand (count at +34,
//     offsets at +36, strings from +100), answered through
//     setCmdResultWebServiceWithString like the generated setters.
//
// Only setters whose complete request was recovered are here; a setter
// that sends one request per list item sends them in the vendor's order
// and stops at the first failing one, as the C code does. Several vendor
// handlers do not clear their request buffer (the bytes past the written
// fields are stack garbage on the OLT); the helper sends zeros there.
//
// The helper receives the request body already parsed, so the vendor's
// "arguement error"/104/105 answers for an unparsable body never apply.

const plainReplyBuf = 256 // setCmdResultWebService reply buffer

// jsonStr is cJSON_GetString(body, name, def).
func (p Params) jsonStr(name, def string) string {
	if _, ok := p[name]; !ok {
		return def
	}
	return p.Str(name)
}

// list returns the objects of the array body[key].
func (p Params) list(key string) ([]Params, bool) {
	raw, ok := p[key]
	if !ok {
		return nil, false
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]Params, 0, len(arr))
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			out = append(out, Params(m))
		} else {
			out = append(out, Params{})
		}
	}
	return out, true
}

// strList returns the string elements of the array body[key] (a cJSON
// string array read through item->valuestring).
func (p Params) strList(key string) ([]string, bool) {
	raw, ok := p[key]
	if !ok {
		return nil, false
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		s, _ := it.(string)
		out = append(out, s)
	}
	return out, true
}

// legacyBody writes params in the legacy layout. It may be applied again
// to the same message (the vendor reuses its buffer across list items),
// then only the fields are overwritten, exactly like the C code.
func legacyBody(m wire.Msg, params ...string) {
	off := 58
	for i, s := range params {
		m.PutU16(wire.QuickCountOff+2*i, uint16(len(s)))
		m.PutString(off, s)
		off += len(s) + 1
	}
}

// plainReply is setCmdResultWebService's reply handling: ok=true when the
// daemon answered "0..." (the caller then prints {"errCode":"0"}); else
// the JSON the vendor writes for the error reply.
func plainReply(reply string) (out []byte, ok bool) {
	if strings.HasPrefix(reply, "0") {
		return nil, true
	}
	f := cemu.GetFrame(0x200)
	defer f.Release()
	f.Sscanf(reply, "%d%s", 0x198, 0x194)
	code := int32(f.U32(0x198))
	toks := cemu.Strtok(f.Str(0x194), "|")
	if len(toks) == 0 && len(reply) > 0 && reply[0] >= '0' && reply[0] <= '9' {
		return errCodeJSON(int(code)), false
	}
	if code <= 99 || code > 1499 {
		return errCodeJSON(102), false
	}
	root := cemu.Object()
	root.AddString("errCode", strconv.Itoa(int(code)))
	arr := cemu.Array()
	root.AddItem("param", arr)
	for _, t := range toks {
		arr.AddString("", t)
	}
	return root.Print(), false
}

var okJSON = []byte(`{"errCode":"0"}`)

// plainCall sends m to sock and applies plainReply. A daemon timeout is
// the vendor's "-1" reply (web_service_cmd copies "-1" on select timeout).
func plainCall(b Backend, sock string, m wire.Msg) (errOut []byte, ok bool, err error) {
	reply, err := b.Query(sock, func(path string) (wire.Msg, error) {
		copy(m[wire.PathOff:wire.PathOff+wire.PathLen], make([]byte, wire.PathLen))
		copy(m[wire.PathOff:], path)
		return m, nil
	}, plainReplyBuf)
	if err != nil {
		if !isTimeout(err) {
			return nil, false, err
		}
		reply = "-1"
	}
	out, ok := plainReply(reply)
	return out, ok, nil
}

func newMsg(code uint16) wire.Msg {
	m, _ := wire.NewMsg(code, "")
	return m
}

type setFn = func(b Backend, p Params, env *Env) ([]byte, error)

// legacySetter: one request with the named parameters (cJSON_GetString
// defaults) in the legacy layout.
func legacySetter(sock string, code uint16, params ...[2]string) setFn {
	return func(b Backend, p Params, _ *Env) ([]byte, error) {
		vals := make([]string, len(params))
		for i, pr := range params {
			vals[i] = p.jsonStr(pr[0], pr[1])
		}
		m := newMsg(code)
		legacyBody(m, vals...)
		out, ok, err := plainCall(b, sock, m)
		if err != nil {
			return nil, err
		}
		if !ok {
			return out, nil
		}
		return okJSON, nil
	}
}

// boolSetter: the command code depends on one parameter being "1"
// (first byte, or the whole string when strcmp is set); no body.
func boolSetter(sock, param string, on, off uint16, strcmp bool) setFn {
	return func(b Backend, p Params, _ *Env) ([]byte, error) {
		v := p.jsonStr(param, "")
		code := off
		if (strcmp && v == "1") || (!strcmp && strings.HasPrefix(v, "1")) {
			code = on
		}
		out, ok, err := plainCall(b, sock, newMsg(code))
		if err != nil {
			return nil, err
		}
		if !ok {
			return out, nil
		}
		return okJSON, nil
	}
}

// perItem runs one legacy request per element of body[listKey] (in the
// vendor's order) with the parameters fn derives from the item; fn
// returning false skips the item. reuse keeps one request buffer across
// items (handlers without a memset per item).
func perItem(sock string, code uint16, listKey string, reuse bool, fn func(item Params) ([]string, bool)) setFn {
	return func(b Backend, p Params, _ *Env) ([]byte, error) {
		items, _ := p.list(listKey)
		var m wire.Msg
		for _, it := range items {
			vals, send := fn(it)
			if !send {
				continue
			}
			if m == nil || !reuse {
				m = newMsg(code)
			}
			legacyBody(m, vals...)
			out, ok, err := plainCall(b, sock, m)
			if err != nil {
				return nil, err
			}
			if !ok {
				return out, nil
			}
		}
		return okJSON, nil
	}
}

// quickJoinSetter: formQuick layout with one parameter made of the named
// field of every list item joined with "," (formDelDbaprofile family),
// answered like setCmdResultWebServiceWithString. Missing "list" answers
// errCode 103 without a request.
func quickJoinSetter(code uint16, field string) setFn {
	return func(b Backend, p Params, _ *Env) ([]byte, error) {
		items, ok := p.list("list")
		if !ok {
			return errCodeJSON(103), nil
		}
		parts := make([]string, len(items))
		for i, it := range items {
			parts[i] = it.jsonStr(field, "")
		}
		return quickSetterSpec{Code: code, Socket: SockPON}.send(b, []string{strings.Join(parts, ",")})
	}
}

// quickEachSetter: one formQuick request per list item carrying the
// item's named field (formDelOntAutoAddConfig, formDelOntUpgradeImage).
func quickEachSetter(code uint16, field string) setFn {
	return func(b Backend, p Params, _ *Env) ([]byte, error) {
		items, ok := p.list("list")
		if !ok {
			return errCodeJSON(103), nil
		}
		var first []byte
		for _, it := range items {
			out, err := quickSetterSpec{Code: code, Socket: SockPON}.send(b, []string{it.jsonStr(field, "")})
			if err != nil {
				return nil, err
			}
			if first == nil {
				first = out // the first write reaches the browser; the vendor keeps sending
			}
		}
		if first == nil {
			return errCodeJSON(103), nil
		}
		return first, nil
	}
}

// send is the quick setter's round trip for already-resolved values.
func (s quickSetterSpec) send(b Backend, vals []string) ([]byte, error) {
	reply, err := b.Query(s.Socket, func(path string) (wire.Msg, error) {
		m, err := wire.NewMsg(s.Code, path)
		if err != nil {
			return nil, err
		}
		_ = m.PutQuick(vals)
		return m, nil
	}, setterBuf)
	if err != nil {
		if isTimeout(err) {
			reply = "-1"
		} else {
			return nil, err
		}
	}
	return setterJSON(reply), nil
}

// macDotted is the vendor's MAC rewrite (fcn @0x4cda0): "aabb:cc..." style
// 17-character addresses become "aabb.ccdd.eeff" by picking fixed
// positions; a shorter input reads NULs.
func macDotted(s string) string {
	at := func(i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	out := []byte{at(0), at(1), at(3), at(4), '.', at(6), at(7), at(9), at(10), '.', at(12), at(13), at(15), at(16)}
	return cemu.CString(out)
}

// macDots replaces bytes 4 and 9 of a copy of s with '.' (formsetIpMacFilterList).
func macDots(s string) string {
	buf := []byte(s)
	for _, i := range []int{4, 9} {
		for len(buf) <= i {
			buf = append(buf, 0)
		}
		buf[i] = '.'
	}
	return cemu.CString(buf)
}

func init() {
	ports := []struct {
		name, handler string
		fn            setFn
	}{
		// ---- formQuick layout, pon_web, setCmdResultWebServiceWithString ----
		{"delDbaprofile", "formDelDbaprofile", quickJoinSetter(1028, "profileid")},
		{"delDsprofile", "formDelDsprofile", quickJoinSetter(1087, "profileid")},
		{"delUsprofile", "formDelUsprofile", quickJoinSetter(1082, "profileid")},
		{"delLineprofile", "formDelLineprofile", quickJoinSetter(1032, "profileid")},
		{"delWifiProfile", "formDelWifiProfile", quickJoinSetter(1142, "profileid")},
		{"delOntMulticastProfile", "formDelMulticastProfile", quickJoinSetter(1136, "profileid")},
		{"delOntUniqueProfile", "formDelOntUniqueProfile", quickJoinSetter(1091, "profileid")},
		{"delOntUpgradeState", "formDelOntUpgradeState", quickJoinSetter(1075, "onuid")},
		{"delOntAutoAddConfig", "formDelOntAutoAddConfig", quickEachSetter(1066, "index")},
		{"delOntUpgradeImage", "formDelOntUpgradeImage", quickEachSetter(1071, "fname")},
		// formSetMqttConfigInfo @0xa9f04: mqtt 232, formQuick layout written by hand.
		{"setNmsConfigInfo", "formSetMqttConfigInfo", func(b Backend, p Params, _ *Env) ([]byte, error) {
			return quickSetterSpec{Code: 232, Socket: SockMQTT}.send(b, []string{
				p.jsonStr("cloudState", "disable"), p.jsonStr("serverIp", ""), p.jsonStr("serverPort", "1883"), p.jsonStr("tenantId", "")})
		}},
		// formSetGlobalLoopDetectInfo @0xa8d48: nldp 212 per port of the "port" string array.
		{"setGlobalLoopDetection", "formSetGlobalLoopDetectInfo", func(b Backend, p Params, _ *Env) ([]byte, error) {
			ports, ok := p.strList("port")
			if !ok {
				return errCodeJSON(103), nil
			}
			var first []byte
			for _, port := range ports {
				out, err := quickSetterSpec{Code: 212, Socket: SockNLDP}.send(b, []string{port,
					p.jsonStr("loopDetectEn", "0"), p.jsonStr("loopVid", ""), p.jsonStr("txIntervalTime", "0"), p.jsonStr("resumeTime", "0")})
				if err != nil {
					return nil, err
				}
				if first == nil {
					first = out
				}
			}
			if first == nil {
				return errCodeJSON(103), nil
			}
			return first, nil
		}},

		// ---- legacy layout, one request --------------------------------------
		{"setAgingTime", "formSetAgingTime", legacySetter(SockNSM, 297, [2]string{"agingTime", ""})},
		{"setDhcpSnoopVlanEn", "formsetDhcpSnoopVlanEn", legacySetter(SockDHCPS, 53, [2]string{"vlanList", ""})},
		{"setMacAgingCfg", "formsetMacAgingCfg", legacySetter(SockNSM, 288, [2]string{"macagingtime", ""})},
		{"setAccessDefaultAction", "formDefaultActionSet", legacySetter(SockNSM, 428, [2]string{"accessStatus", "0"})},
		{"clearPackageStatistics", "formClearPackageStatistics", legacySetter(SockNSM, 285)},
		{"clearPortTreeStatistics", "formCleasrMstpPortStatistics", legacySetter(SockMSTP, 591)},
		{"resetRadiusInfo", "formResetRadiusInfo", legacySetter(SockUM, 228)},
		{"setMulRouterTab", "formsetMulRouterTab", legacySetter(SockNSM, 96, [2]string{"port", ""}, [2]string{"vlanId", ""})},
		{"setServicePort", "formSetServicePort", legacySetter(SockNSM, 424, [2]string{"telnetport", "23"}, [2]string{"sshport", "22"},
			[2]string{"httpport", "80"}, [2]string{"httpsport", "443"}, [2]string{"snmpport", "161"})},
		// formsetPortArpAttackInfo @0x469c0: without arpReceptRate nothing is sent.
		{"setPortArpAttackInfo", "formsetPortArpAttackInfo", func(b Backend, p Params, env *Env) ([]byte, error) {
			if _, ok := p["arpReceptRate"]; !ok {
				return okJSON, nil
			}
			return legacySetter(SockNSM, 299, [2]string{"arpReceptRate", ""})(b, p, env)
		}},
		// formsetIpMacFilterList @0x4fb30: mac bytes 4 and 9 become '.'.
		{"setIpMacFilterList", "formsetIpMacFilterList", func(b Backend, p Params, _ *Env) ([]byte, error) {
			m := newMsg(357)
			legacyBody(m, macDots(p.jsonStr("mac", "")), p.jsonStr("vlanId", ""))
			return finish(plainCall(b, SockNSM, m))
		}},
		// formSetArpTable @0x45ee0: mac "xxxx-xxxx-xxxx" -> "xxxx.xxxx.xxxx", port -> "vlan1.<port>".
		{"setArpTable", "formSetArpTable", func(b Backend, p Params, _ *Env) ([]byte, error) {
			f := cemu.GetFrame(0x540)
			defer f.Release()
			f.Sscanf(p.jsonStr("mac", ""), "%4s-%4s-%4s", 0x51c, 0x524, 0x52c)
			dotted := f.Str(0x51c) + "." + f.Str(0x524) + "." + f.Str(0x52c)
			m := newMsg(295)
			legacyBody(m, p.jsonStr("ip", ""), dotted, "vlan1."+p.jsonStr("port", ""))
			return finish(plainCall(b, SockNSM, m))
		}},
		// formSetAuthGlobalInfo @0x6a104: authd 465 [authIp] then 466 [shareKey], each only when non-empty.
		{"setAuthGlobalInfo", "formSetAuthGlobalInfo", func(b Backend, p Params, _ *Env) ([]byte, error) {
			for _, q := range []struct {
				code uint16
				key  string
			}{{465, "authIp"}, {466, "shareKey"}} {
				v := p.jsonStr(q.key, "")
				if v == "" {
					continue
				}
				m := newMsg(q.code)
				legacyBody(m, v)
				if out, ok, err := plainCall(b, SockAUTHD, m); err != nil || !ok {
					return out, err
				}
			}
			return okJSON, nil
		}},
		// formAddStaticRoute @0x45448: an edit first deletes the route with the original next hop (nsm 292), then adds (nsm 291).
		{"setStaticRouteInfo", "formAddStaticRoute", func(b Backend, p Params, _ *Env) ([]byte, error) {
			dest, mask := p.jsonStr("destIp", ""), p.jsonStr("mask", "")
			if strings.HasPrefix(p.jsonStr("action", ""), "e") {
				orig, ok := p["originData"].(map[string]any)
				if !ok {
					return errCodeJSON(105), nil
				}
				m := newMsg(292)
				legacyBody(m, dest, mask, Params(orig).jsonStr("nextHop", ""))
				if out, ok, err := plainCall(b, SockNSM, m); err != nil || !ok {
					return out, err
				}
			}
			m := newMsg(291)
			legacyBody(m, dest, mask, p.jsonStr("nextHop", ""))
			return finish(plainCall(b, SockNSM, m))
		}},
		// formSetAppAclInfo @0xa88e0: nsm 334 [port, aclId] per port of the "port" string array.
		{"setAppAclInfo", "formSetAppAclInfo", func(b Backend, p Params, _ *Env) ([]byte, error) {
			ports, _ := p.strList("port")
			acl := p.jsonStr("aclId", "")
			for _, port := range ports {
				m := newMsg(334)
				legacyBody(m, port, acl)
				if out, ok, err := plainCall(b, SockNSM, m); err != nil || !ok {
					return out, err
				}
			}
			return okJSON, nil
		}},
		// formSetQinqVlanInfo @0x695d4: nsm 435 [port, startvlan, destvlan] per port (endvlan is never sent).
		{"setQinqVlanInfo", "formSetQinqVlanInfo", func(b Backend, p Params, _ *Env) ([]byte, error) {
			ports, ok := p.strList("port")
			if !ok {
				return errCodeJSON(103), nil
			}
			for _, port := range ports {
				m := newMsg(435)
				legacyBody(m, port, p.jsonStr("startvlan", ""), p.jsonStr("destvlan", ""))
				if out, ok, err := plainCall(b, SockNSM, m); err != nil || !ok {
					return out, err
				}
			}
			return okJSON, nil
		}},
		// formSetVlanTransformInfo @0x67e80: nsm 432 [port, start or "start-end", destvlan] per port; one buffer for all ports.
		{"setVlanTransformInfo", "formSetVlanTransformInfo", func(b Backend, p Params, _ *Env) ([]byte, error) {
			ports, _ := p.strList("port")
			start, end, dest := p.jsonStr("startvlan", ""), p.jsonStr("endvlan", ""), p.jsonStr("destvlan", "")
			rng := start
			if cAtoi(start) != cAtoi(end) {
				rng = start + "-" + end
			}
			m := newMsg(432)
			for _, port := range ports {
				legacyBody(m, port, rng, dest)
				if out, ok, err := plainCall(b, SockNSM, m); err != nil || !ok {
					return out, err
				}
			}
			return okJSON, nil
		}},

		// ---- legacy layout, code chosen by a boolean parameter ---------------
		{"setDscpQueueEn", "formSetDscpQueueEn", boolSetter(SockNSM, "dscpEn", 348, 349, false)},
		{"setIgmpSnoopEn", "formsetIgmpSnoopEn", boolSetter(SockNSM, "igmpSnoopingEn", 71, 72, true)},
		{"setNetAuthEn", "formSetNetAuthEn", boolSetter(SockAUTHD, "authEn", 462, 463, false)},
		{"setDhcpSnoopEn", "formsetDhcpSnoopEn", boolSetter(SockDHCPS, "dhcpSnoopEn", 31, 32, false)},
		{"setSnmpNoticeGlobal", "formSetSnmpNoticeGlobal", boolSetter(SockUM, "trapEn", 414, 415, false)},

		// ---- legacy layout, one request per list item -------------------------
		// formDelAppAclList @0xa8b00: nsm 336 [port, aclId] for every port of every item.
		{"delAppAclList", "formDelAppAclList", func(b Backend, p Params, _ *Env) ([]byte, error) {
			items, _ := p.list("list")
			for _, it := range items {
				ports, _ := it.strList("port")
				acl := it.jsonStr("aclId", "")
				for _, port := range ports {
					m := newMsg(336)
					legacyBody(m, port, acl)
					if out, ok, err := plainCall(b, SockNSM, m); err != nil || !ok {
						return out, err
					}
				}
			}
			return okJSON, nil
		}},
		// formDelArpTable @0x462c4: nsm 296 [ip] with u16 7 (dhcp) / 6 (static) at +36.
		{"delArpTable", "formDelArpTable", func(b Backend, p Params, _ *Env) ([]byte, error) {
			items, ok := p.list("list")
			if !ok {
				// the vendor writes the bare text "ERROR": not JSON, so the
				// agent is sent to the web UI, which answers the same
				return nil, errors.New("formDelArpTable: no list (web UI answers ERROR)")
			}
			for _, it := range items {
				m := newMsg(296)
				legacyBody(m, it.jsonStr("ip", ""))
				switch it.jsonStr("type", "") {
				case "dhcp":
					m.PutU16(36, 7)
				case "static":
					m.PutU16(36, 6)
				}
				if out, ok, err := plainCall(b, SockNSM, m); err != nil || !ok {
					return out, err
				}
			}
			return okJSON, nil
		}},
		// formDelDhcpClientList @0x5de4c: dhcps 55 [ipaddr up to the first space].
		{"delDhcpClientList", "formDelDhcpClientList", perItem(SockDHCPS, 55, "list", false, func(it Params) ([]string, bool) {
			ip, _, _ := strings.Cut(it.jsonStr("ipaddr", ""), " ")
			return []string{ip}, true
		})},
		// formdelIpMacFilterList @0x4fdf0: nsm 358 [mac with '.' at 4 and 9, vlanId].
		{"delIpMacFilterList", "formdelIpMacFilterList", perItem(SockNSM, 358, "list", false, func(it Params) ([]string, bool) {
			return []string{macDots(it.jsonStr("mac", "")), it.jsonStr("vlanId", "")}, true
		})},
		// formDelMstpInstanceList @0x52bf0: mstp 577 [instanceId].
		{"delMstpInstanceList", "formDelMstpInstanceList", perItem(SockMSTP, 577, "list", false, func(it Params) ([]string, bool) {
			return []string{it.jsonStr("instanceId", "")}, true
		})},
		// formdelMulRouterTab @0x5ab48: nsm 98 [port, vlanId]; missing list -> 103.
		{"delMulRouterTab", "formdelMulRouterTab", func(b Backend, p Params, env *Env) ([]byte, error) {
			if _, ok := p.list("list"); !ok {
				return errCodeJSON(103), nil
			}
			return perItem(SockNSM, 98, "list", false, func(it Params) ([]string, bool) {
				return []string{it.jsonStr("port", ""), it.jsonStr("vlanId", "")}, true
			})(b, p, env)
		}},
		// formDelQinqVlanInfo @0x6999c: nsm 436 [portName, startvlan, destvlan]; one buffer for all items.
		{"delQinqVlanInfo", "formDelQinqVlanInfo", perItem(SockNSM, 436, "list", true, func(it Params) ([]string, bool) {
			return []string{it.jsonStr("portName", ""), it.jsonStr("startvlan", ""), it.jsonStr("destvlan", "")}, true
		})},
		// formDelVlanTransformInfo @0x68554: nsm 433 [portName, startvlan, destvlan] (the "start-end" branch is dead:
		// the vendor reads startvlan twice); one buffer for all items.
		{"delVlanTransformInfo", "formDelVlanTransformInfo", perItem(SockNSM, 433, "list", true, func(it Params) ([]string, bool) {
			return []string{it.jsonStr("portName", ""), it.jsonStr("startvlan", ""), it.jsonStr("destvlan", "")}, true
		})},
		// formDelSnmpCommunityList @0x6d5e4: um 400 [communityName]; one buffer for all items.
		{"delSnmpCommunityList", "formDelSnmpCommunityList", perItem(SockUM, 400, "list", true, func(it Params) ([]string, bool) {
			return []string{it.jsonStr("communityName", "")}, true
		})},
		// formdelStaticMacRule @0x4e12c: nsm 384 [dotted mac, vlanId, port].
		{"delStaticMacRule", "formdelStaticMacRule", perItem(SockNSM, 384, "list", false, func(it Params) ([]string, bool) {
			return []string{macDotted(it.jsonStr("mac", "")), it.jsonStr("vlanId", ""), it.jsonStr("port", "")}, true
		})},
		// formDelAccessList @0x47650: nsm 429 [service_name, svindex], items in reverse order, one buffer;
		// an item without svindex ends the loop.
		{"delAccessList", "formDelAccessList", func(b Backend, p Params, _ *Env) ([]byte, error) {
			items, _ := p.list("list")
			m := newMsg(429)
			for i := len(items) - 1; i >= 0; i-- {
				it := items[i]
				if _, ok := it["svindex"]; !ok {
					break
				}
				legacyBody(m, it.jsonStr("service_name", ""), it.jsonStr("svindex", ""))
				if out, ok, err := plainCall(b, SockNSM, m); err != nil || !ok {
					return out, err
				}
			}
			return okJSON, nil
		}},
		// formDelPortAggregatorList @0x3d954: nsm 520 [port] for every port of every group, one buffer, then sleep(1).
		{"delPortAggregatorList", "formDelPortAggregatorList", func(b Backend, p Params, _ *Env) ([]byte, error) {
			items, _ := p.list("list")
			m := newMsg(520)
			for _, it := range items {
				ports, ok := it.strList("port")
				if !ok {
					return errCodeJSON(103), nil
				}
				for _, port := range ports {
					legacyBody(m, port)
					if out, ok, err := plainCall(b, SockNSM, m); err != nil || !ok {
						return out, err
					}
				}
			}
			sysx.Sleep(1_000_000_000)
			return okJSON, nil
		}},
	}
	for _, s := range ports {
		addPort(&Endpoint{Name: s.name, Op: "set", Source: "daemon", Handler: s.handler, fn: s.fn})
	}
}

// finish turns a plainCall result into the handler's answer.
func finish(out []byte, ok bool, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	if !ok {
		return out, nil
	}
	return okJSON, nil
}
