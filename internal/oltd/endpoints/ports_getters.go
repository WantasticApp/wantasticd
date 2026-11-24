package endpoints

import (
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/oltd/cemu"
	"wantastic-agent/internal/oltd/wire"
)

// Hand ports of bespoke vendor getters. Each one follows the tools/oltre
// trace of the named handler (python3 -I tools/oltre/oltre.py ... trace
// <name>); frame offsets, buffer sizes, request layouts and key order are
// the vendor's. A getter returns an error (and the agent uses the web UI)
// only when a daemon request fails.

// legacy builds the request shape of the older handlers: code, the
// parameter's length as u16 at +34 and the parameter string at +58
// (getSysStatus sends "mng0"/4 and "0.0.0.0"/7 the same way).
func legacy(code uint16, param string) func(string) (wire.Msg, error) {
	return func(path string) (wire.Msg, error) {
		m, err := wire.NewMsg(code, path)
		if err != nil {
			return nil, err
		}
		m.PutU16(wire.QuickCountOff, uint16(len(param)))
		m.PutString(58, param)
		return m, nil
	}
}

// strVar is websGetVar(wp, name, def): def when the variable is absent.
func (p Params) strVar(name, def string) string {
	if _, ok := p[name]; !ok {
		return def
	}
	return p.Str(name)
}

// addCols adds row[key] = frame string for each (key, offset) pair.
func addCols(row *cemu.JSON, f *cemu.Frame, cols ...any) {
	for i := 0; i+1 < len(cols); i += 2 {
		row.AddString(cols[i].(string), f.Str(cols[i+1].(int)))
	}
}

func errCodeJSON(code int) []byte { return []byte(`{"errCode":"` + strconv.Itoa(code) + `"}`) }

// ---- getAccessList: formGetAccessList @0x47130 ---------------------------
//
// nsm 427 (buf 2048) -> accessStatus is the raw reply; nsm 426 (buf 2048)
// -> one rule per line "svindex,real_index,service_name,ip_start,ip_end,action".

func getAccessList(b Backend, _ Params, _ *Env) ([]byte, error) {
	root := cemu.Object()
	status, err := b.Query(SockNSM, simpleMsg(427), 2048)
	if err != nil {
		return nil, err
	}
	root.AddString("accessStatus", status)
	rules, err := b.Query(SockNSM, simpleMsg(426), 2048)
	if err != nil {
		return nil, err
	}
	list := cemu.Array()
	root.AddItem("list", list)
	f := cemu.GetFrame(0xcd0)
	defer f.Release()
	for _, line := range cemu.Strtok(rules, "\n") {
		f.Zero(0xc60, 8)
		f.Zero(0xc68, 8)
		f.Zero(0xc78, 16)
		f.Zero(0xcc8, 80)
		row := cemu.Object()
		f.Sscanf(line, "%[^,],%[^,],%[^,],%[^,],%[^,],%s", 0xc60, 0xc68, 0xc78, 0xcc8, 0xca8, 0xc88)
		list.AddItem("", row)
		addCols(row, f, "svindex", 0xc60, "real_index", 0xc68, "service_name", 0xc78,
			"ip_start", 0xcc8, "ip_end", 0xca8, "action", 0xc88)
	}
	return root.Print(), nil
}

// ---- getArpTableList: formGetArpTableList @0x45978 -----------------------
//
// nsm 293 with "brief" (legacy layout, buf 0xc800) -> agingTime is the raw
// reply; nsm 294 (buf 0xc800) -> one entry per line
// "agingTime ip mac port type"; a line containing "finish" ends the list.

func getArpTableList(b Backend, _ Params, _ *Env) ([]byte, error) {
	root := cemu.Object()
	aging, err := b.Query(SockNSM, legacy(293, "brief"), 0xc800)
	if err != nil {
		return nil, err
	}
	root.AddString("agingTime", aging)
	entries, err := b.Query(SockNSM, simpleMsg(294), 0xc800)
	if err != nil {
		return nil, err
	}
	list := cemu.Array()
	root.AddItem("list", list)
	f := cemu.GetFrame(0xccb0)
	defer f.Release()
	for _, line := range cemu.Strtok(entries, "\n") {
		f.Zero(0xcc70, 24)
		f.Zero(0xcc88, 24)
		f.Zero(0xcc90, 8)
		f.Zero(0xcc9c, 12)
		f.Zero(0xcca4, 8)
		if strings.Contains(line, "finish") {
			break
		}
		row := cemu.Object()
		f.Sscanf(line, "%s%s%s%s%s", 0xcca4, 0xcc70, 0xcc88, 0xcc9c, 0xcc90)
		list.AddItem("", row)
		addCols(row, f, "ip", 0xcc70, "mac", 0xcc88, "type", 0xcc90, "port", 0xcc9c, "agingTime", 0xcca4)
	}
	return root.Print(), nil
}

// ---- getPortTreeStatusList: formgetPortTreeStatusList @0x5428c -----------
//
// ?instanceId= is required (errCode 105 otherwise). mstp 584 (buf 4096)
// -> one instance id per line; mstp 582 with the instance id (legacy
// layout, buf 4096) -> one port per line
// "portName domainRoot portRole portStatus bridgeId port priority portPathCost".

func getPortTreeStatusList(b Backend, p Params, _ *Env) ([]byte, error) {
	inst := p.strVar("instanceId", "")
	if inst == "" {
		return errCodeJSON(105), nil
	}
	ids, err := b.Query(SockMSTP, simpleMsg(584), 4096)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	instList := cemu.Array()
	root.AddItem("instanceList", instList)
	f := cemu.GetFrame(0x16a0)
	defer f.Release()
	for _, line := range cemu.Strtok(ids, "\n") {
		f.Zero(0x1574, 10)
		f.Sscanf(line, "%s", 0x1574)
		instList.AddString("", f.Str(0x1574))
	}
	ports, err := b.Query(SockMSTP, legacy(582, inst), 4096)
	if err != nil {
		return nil, err
	}
	n := 1
	for _, line := range cemu.Strtok(ports, "\n") {
		for _, off := range []int{0x1590, 0x15ac, 0x15c8, 0x15e4, 0x1600, 0x161c, 0x1638, 0x1654, 0x1670} {
			f.Zero(off, 25)
		}
		f.Sscanf(line, "%s%s%s%s%s%s%s%s\n", 0x1590, 0x1600, 0x15c8, 0x15e4, 0x161c, 0x1638, 0x1654, 0x1670)
		row := cemu.Object()
		list.AddItem("", row)
		f.Write(0x15ac, strconv.Itoa(n))
		addCols(row, f, "portNum", 0x15ac, "portName", 0x1590, "portRole", 0x15c8, "portStatus", 0x15e4,
			"domainRoot", 0x1600, "bridgeId", 0x161c, "port", 0x1638, "priority", 0x1654, "portPathCost", 0x1670)
		n++
	}
	return root.Print(), nil
}

// ---- getIgmpVlanInfo: formgetIgmpVlanInfo @0x59068 -----------------------
//
// nsm 85 (buf 8192, no parameters) -> one VLAN per line, ten whitespace
// separated fields; the optional ?vlanId= is echoed back as mulVlanId
// ("" when absent, websGetVar default NULL).

func getIgmpVlanInfo(b Backend, p Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockNSM, simpleMsg(85), 8192)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("vlanList", list)
	f := cemu.GetFrame(0x2500)
	defer f.Release()
	for _, line := range cemu.Strtok(reply, "\n") {
		f.Zero(0x2460, 4)
		f.Zero(0x2468, 8)
		f.Zero(0x2470, 8)
		f.Zero(0x2478, 8)
		f.Zero(0x2488, 16)
		f.Zero(0x2494, 12)
		f.Zero(0x249c, 8)
		f.Zero(0x24a4, 8)
		f.Zero(0x24ac, 8)
		f.Zero(0x24b4, 8)
		f.Zero(0x24d4, 32)
		f.Sscanf(line, "%s%s%s%s%s%s%s%s%s%s", 0x2490, 0x2460, 0x2470, 0x2488, 0x2494, 0x249c, 0x24a4, 0x24ac, 0x24b4, 0x24d4)
		row := cemu.Object()
		list.AddItem("", row)
		addCols(row, f, "igmpVersion", 0x2460, "fastleave", 0x249c, "maxResponseTime", 0x2470, "mulVlanEn", 0x2488,
			"vlanEn", 0x2494, "vlanId", 0x2490, "reportsup", 0x24ac, "query", 0x24b4, "sourceip", 0x24d4)
	}
	root.AddString("mulVlanId", p.strVar("vlanId", ""))
	return root.Print(), nil
}

// ---- getPortOptical: formGetPortOpticalList @0x77ee8 ---------------------
//
// nsm 792 (buf 1024) -> one port per line, 14 comma separated fields. The
// buffers are zeroed once (stale values carry over to short lines); PON
// ports get rxPower "--"; portNum is a running counter.

func getPortOptical(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockNSM, simpleMsg(792), 1024)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	f := cemu.GetFrame(0x980)
	defer f.Release()
	n := 1
	for _, line := range cemu.Strtok(reply, "\n") {
		f.Sscanf(line, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%s",
			0x868, 0x870, 0x878, 0x888, 0x890, 0x898, 0x8d4, 0x8e8, 0x8c0, 0x92c, 0x940, 0x908, 0x910, 0x918)
		if strings.HasPrefix(f.Str(0x868), "pon") {
			f.Write(0x898, "--")
		}
		row := cemu.Object()
		list.AddItem("", row)
		f.Write(0x880, strconv.Itoa(n))
		addCols(row, f, "portNum", 0x880, "portName", 0x868, "temperature", 0x870, "supVol", 0x878,
			"txBiasCur", 0x888, "txPower", 0x890, "rxPower", 0x898, "name", 0x8d4, "oui", 0x8e8,
			"productname", 0x8c0, "version", 0x92c, "sn", 0x940, "date", 0x908, "connector", 0x910, "wavelen", 0x918)
		n++
	}
	return root.Print(), nil
}

// ---- getSpanningTreeInfo: formGetMstpGlobalInfo @0x50e78 -----------------
//
// mstp 561 (buf 512) -> one line of 18 whitespace separated fields; the
// 15th is the topology change age in seconds (%u), printed as
// "%ud %uh %um %us" via pal_time_sec2tm.

func getSpanningTreeInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockMSTP, simpleMsg(561), 512)
	if err != nil {
		return nil, err
	}
	f := cemu.GetFrame(0x7c0)
	defer f.Release()
	f.Sscanf(reply, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%u%s%s%s",
		0x10, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x150, 0x40, 0x58, 0x70, 0x78, 0x80, 0x88, 0xa0, 0x790, 0x100, 0x108, 0x148)
	root := cemu.Object()
	addCols(root, f, "treeStatusEn", 0x10, "treeVersion", 0x18, "agingTime", 0x1c, "helloTime", 0x20,
		"forwardDelay", 0x24, "maxHopCount", 0x28, "bridgePriority", 0x150, "bridgeId", 0x40, "rootBridgeId", 0x58,
		"rootDomainId", 0x70, "rootPort", 0x78, "rootPathCost", 0x80, "inRootPathCost", 0x88, "topoStatus", 0xa0)
	secs := f.U32(0x790)
	hours := secs / 3600 // pal_time_sec2tm: s, m, h (no days)
	days, hrs := int32(hours)/24, int32(hours)%24
	age := strconv.FormatUint(uint64(uint32(days)), 10) + "d " + strconv.FormatUint(uint64(uint32(hrs)), 10) + "h " +
		strconv.FormatUint(uint64(secs/60%60), 10) + "m " + strconv.FormatUint(uint64(secs%60), 10) + "s"
	if len(age) > 31 {
		age = age[:31] // snprintf(buf, 32, ...)
	}
	root.AddString("topoChangeTime", age)
	addCols(root, f, "domain", 0x100, "correctionLevel", 0x108, "summary", 0x148)
	return root.Print(), nil
}

// ---- getRadiusInfo: formGetRadiusInfo @0x4b270 ---------------------------
//
// um 227 (buf 256) -> 19 ';' separated fields in 33-byte buffers; a field
// starting with '-' means unset (""); enablepwd is base64 encoded.

func getRadiusInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockUM, simpleMsg(227), 256)
	if err != nil {
		return nil, err
	}
	f := cemu.GetFrame(0x3a0)
	defer f.Release()
	f.Sscanf(reply, "%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%s",
		0x3a0, 0x37f, 0x35e, 0x33d, 0x31c, 0x2fb, 0x2da, 0x2b9, 0x298, 0x277, 0x256, 0x235, 0x214, 0x1f3, 0x1d2, 0x1b1, 0x190, 0x14e, 0x12d)
	dash := func(off int) string {
		s := f.Str(off)
		if strings.HasPrefix(s, "-") {
			return ""
		}
		return s
	}
	root := cemu.Object()
	root.AddString("aaaMode", dash(0x3a0))
	root.AddString("radiusPriServer", dash(0x37f))
	root.AddString("radiusPriSharedKey", dash(0x35e))
	root.AddString("radiusPriPort", f.Str(0x33d))
	root.AddString("radiusPriTimeout", f.Str(0x31c))
	root.AddString("radiusSecServer", dash(0x2fb))
	root.AddString("radiusSecSharedKey", dash(0x2da))
	root.AddString("radiusSecPort", f.Str(0x2b9))
	root.AddString("radiusSecTimeout", f.Str(0x298))
	root.AddString("tacacsPriServer", dash(0x277))
	root.AddString("tacPriSharedKey", dash(0x256))
	root.AddString("tacPriPort", f.Str(0x235))
	root.AddString("tacPriTimeout", f.Str(0x214))
	root.AddString("tacacsSecServer", dash(0x1f3))
	root.AddString("tacSecSharedKey", dash(0x1d2))
	root.AddString("tacSecPort", f.Str(0x1b1))
	root.AddString("tacSecTimeout", f.Str(0x190))
	pwd := ""
	if s := f.Str(0x14e); !strings.HasPrefix(s, "-") {
		pwd = base64.StdEncoding.EncodeToString([]byte(s))
	}
	root.AddString("enablepwd", pwd)
	root.AddString("enablePasswordCheckEn", f.Str(0x12d))
	return root.Print(), nil
}

// ---- getTaskInfo: formGetTaskInfo @0x48ee8 -------------------------------
//
// um 218 (buf 256) -> "autosaveday,autosavehour,autosaveminute,
// autobackupday,autobackuphour,autobackupminute,autobackupserver";
// um 239 (buf 256) -> "oltrebootmode,weekday,monthday,oltreboothour,oltrebootmin".

func getTaskInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	root := cemu.Object()
	f := cemu.GetFrame(0x600)
	defer f.Release()
	save, err := b.Query(SockUM, simpleMsg(218), 256)
	if err != nil {
		return nil, err
	}
	f.Sscanf(save, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%s", 0x550, 0x558, 0x560, 0x568, 0x570, 0x578, 0x598)
	addCols(root, f, "autosaveday", 0x550, "autosavehour", 0x558, "autosaveminute", 0x560, "autobackupday", 0x568,
		"autobackuphour", 0x570, "autobackupminute", 0x578, "autobackupserver", 0x598)
	reboot, err := b.Query(SockUM, simpleMsg(239), 256)
	if err != nil {
		return nil, err
	}
	f.Sscanf(reboot, "%[^,],%[^,],%[^,],%[^,],%s", 0x5e8, 0x5a8, 0x5b8, 0x5c8, 0x5d8)
	addCols(root, f, "oltrebootmode", 0x5e8, "weekday", 0x5a8, "monthday", 0x5b8, "oltreboothour", 0x5c8, "oltrebootmin", 0x5d8)
	return root.Print(), nil
}

// ---- getServicePort: formGetServicePort @0x47c7c -------------------------
//
// nsm 423 (buf 128) -> "telnetport,sshport,httpport,httpsport,snmpport".

func getServicePort(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockNSM, simpleMsg(423), 128)
	if err != nil {
		return nil, err
	}
	f := cemu.GetFrame(0x500)
	defer f.Release()
	f.Sscanf(reply, "%[^,],%[^,],%[^,],%[^,],%s", 0x4d0, 0x4d8, 0x4e0, 0x4e8, 0x4f0)
	root := cemu.Object()
	addCols(root, f, "telnetport", 0x4d0, "sshport", 0x4d8, "httpport", 0x4e0, "httpsport", 0x4e8, "snmpport", 0x4f0)
	return root.Print(), nil
}

// ---- getSnmpNoticeList: formGetSnmpNoticeList @0x6efd8 -------------------
//
// um 411 (buf 256) -> first line "trapEn", then one trap host per line
// "destHost securityWord udpPort securityMode securityLevel"
// (securityLevel "none" prints as "--").

func getSnmpNoticeList(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockUM, simpleMsg(411), 256)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	f := cemu.GetFrame(0x5d0)
	defer f.Release()
	lines := cemu.Strtok(reply, "\n")
	if len(lines) > 0 {
		f.Sscanf(lines[0], "%s", 0x55c)
		lines = lines[1:]
	}
	root.AddString("trapEn", f.Str(0x55c))
	list := cemu.Array()
	root.AddItem("list", list)
	for _, line := range lines {
		f.Zero(0x570, 16)
		f.Zero(0x5a4, 33)
		f.Zero(0x578, 8)
		f.Zero(0x580, 8)
		f.Zero(0x5c4, 32)
		row := cemu.Object()
		list.AddItem("", row)
		f.Sscanf(line, "%s%s%s%s%s", 0x570, 0x5a4, 0x578, 0x580, 0x5c4)
		addCols(row, f, "destHost", 0x570, "securityWord", 0x5a4, "udpPort", 0x578, "securityMode", 0x580)
		level := f.Str(0x5c4)
		if level == "none" {
			level = "--"
		}
		row.AddString("securityLevel", level)
	}
	return root.Print(), nil
}

// ---- getNmsConfigInfo: formGetMqttConfigInfo @0x9b6c ---------------------
//
// mqtt 231 (buf 12288, empty formQuick body) -> "cloudState,serverIp,
// serverPort,tenantId".

func getNmsConfigInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockMQTT, func(path string) (wire.Msg, error) {
		m, err := wire.NewMsg(231, path)
		if err != nil {
			return nil, err
		}
		_ = m.PutQuick(nil)
		return m, nil
	}, 12288)
	if err != nil {
		return nil, err
	}
	f := cemu.GetFrame(0x3540)
	defer f.Release()
	f.Sscanf(reply, "%[^,],%[^,],%[^,],%[^\n]", 0x348c, 0x34a4, 0x34ac, 0x3534)
	root := cemu.Object()
	addCols(root, f, "cloudState", 0x348c, "serverIp", 0x34a4, "serverPort", 0x34ac, "tenantId", 0x3534)
	return root.Print(), nil
}

// ---- getMacAddrList: formgetMacAddrList @0x4c71c -------------------------
//
// nsm 287 (buf 16384) -> macagingtime (first word); nsm 286 (buf 16384)
// -> one entry per line "port vlan mac type"; a port starting with "vl"
// is rewritten to "vl<port>  " (sic, two sprintf passes in the vendor).

func getMacAddrList(b Backend, _ Params, _ *Env) ([]byte, error) {
	aging, err := b.Query(SockNSM, simpleMsg(287), 16384)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	f := cemu.GetFrame(0x4d0)
	defer f.Release()
	f.Sscanf(aging, "%s", 0x4c8)
	root.AddString("macagingtime", f.Str(0x4c8))
	entries, err := b.Query(SockNSM, simpleMsg(286), 16384)
	if err != nil {
		return nil, err
	}
	for _, line := range cemu.Strtok(entries, "\n") {
		f.Zero(0x4ac, 16)
		f.Zero(0x49c, 16)
		f.Zero(0x470, 10)
		f.Zero(0x48c, 25)
		f.Zero(0x4bc, 16)
		f.Sscanf(line, "%s%s%s%s", 0x4ac, 0x470, 0x48c, 0x4bc)
		if strings.HasPrefix(f.Str(0x4ac), "vl") {
			f.Write(0x464, "vl"+f.Str(0x4ac)+" ")
			f.Write(0x4ac, f.Str(0x464)+" ")
		}
		row := cemu.Object()
		list.AddItem("", row)
		addCols(row, f, "port", 0x4ac, "mac", 0x48c, "vlan", 0x470, "type", 0x4bc)
	}
	return root.Print(), nil
}

// ---- getSystemTimeInfo: formGetSystemTimeInfo @0x36db8 -------------------
//
// sntp 166 (buf 128) -> "date,time,timeType,tz,sntppserver,sntpsserver";
// a reply containing "error" answers errCode 101. The time zone is
// rewritten from "+HHMM"/"-HHMM" to "[-]H[.5]" unless timeType starts
// with 'l'; "0" stays "0".

func getSystemTimeInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockSNTP, simpleMsg(166), 128)
	if err != nil {
		return nil, err
	}
	if strings.Contains(reply, "error") {
		return errCodeJSON(101), nil
	}
	f := cemu.GetFrame(0x540)
	defer f.Release()
	f.Sscanf(reply, "%[^,],%[^,],%[^,],%[^,],%[^,],%s", 0x48, 0x20, 0x30, 0x28, 0x60, 0x78)
	tz := f.Str(0x28)
	out := make([]byte, 0, 4)
	for i := 0; i <= 2; i++ {
		if strings.HasPrefix(f.Str(0x30), "l") {
			break
		}
		if i == 0 && (len(tz) < 1 || tz[0] != '-') {
			continue
		}
		if i == 1 && len(tz) > 1 && tz[1] == '0' {
			continue
		}
		var c byte
		if i < len(tz) {
			c = tz[i]
		}
		out = append(out, c)
	}
	f.Write(0x7c, cemu.CString(out))
	if strings.Contains(tz, "30") {
		f.Write(0x7c, f.Str(0x7c)+".5")
	}
	f.Write(0x48, f.Str(0x48)+" "+f.Str(0x20))
	root := cemu.Object()
	root.AddString("systemTime", f.Str(0x48))
	root.AddString("currentTime", f.Str(0x48))
	root.AddString("timeType", f.Str(0x30))
	if tz == "0" {
		root.AddString("timeZone", "0")
	} else {
		root.AddString("timeZone", f.Str(0x7c))
	}
	root.AddString("sntppserver", f.Str(0x60))
	root.AddString("sntpsserver", f.Str(0x78))
	return root.Print(), nil
}

// ---- getDhcpClientList: formgetDhcpClientList @0x5e24c -------------------
//
// dhcps 54 (buf 8192) -> one lease per line
// "ipaddr,macaddr,remaintime,?,vlan,interface"; expire is
// now+remaintime as "%04d-%02d-%02d %02d:%02d" in UTC (get_time_string),
// index a running number.

var unixNow = func() int64 { return time.Now().Unix() }

func getDhcpClientList(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockDHCPS, simpleMsg(54), 8192)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	f := cemu.GetFrame(0x2560)
	defer f.Release()
	n := 0
	for _, line := range cemu.Strtok(reply, "\n") {
		f.Zero(0x2540, 224)
		f.Sscanf(line, "%[^,],%[^,],%[^,],%[^,],%[^,],%s", 0x2540, 0x2520, 0x24a0, 0x2480, 0x24e0, 0x2500)
		row := cemu.Object()
		list.AddItem("", row)
		addCols(row, f, "ipaddr", 0x2540, "macaddr", 0x2520, "interface", 0x2500, "vlan", 0x24e0)
		expire := ""
		if t := unixNow() + int64(int32(cAtoi(f.Str(0x24a0)))); t != -1 {
			expire = time.Unix(t, 0).UTC().Format("2006-01-02 15:04")
		}
		row.AddString("expire", expire)
		row.AddString("remaintime", f.Str(0x24a0))
		n++
		row.AddNumber("index", float64(n))
	}
	return root.Print(), nil
}

// ---- getDhcpSnoopList: formgetDhcpSnoopList @0x5b4d8 ---------------------
//
// dhcps 40 (buf 8192) -> line 1 dhcpSnoopEn, line 2 vlanList, then one
// port per line with 27 comma separated fields; the option-82 flags print
// as booleans ('1' = true), "null" definitions print as "".

func getDhcpSnoopList(b Backend, _ Params, _ *Env) ([]byte, error) {
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	root.AddString("dhcpRelayEn", "0")
	reply, err := b.Query(SockDHCPS, simpleMsg(40), 8192)
	if err != nil {
		return nil, err
	}
	lines := cemu.Strtok(reply, "\n")
	head := func() string {
		if len(lines) == 0 {
			return ""
		}
		s := lines[0]
		lines = lines[1:]
		return s
	}
	root.AddString("dhcpSnoopEn", head())
	root.AddString("vlanList", head())
	f := cemu.GetFrame(0x2620)
	defer f.Release()
	nullDef := func(off int) string {
		if strings.HasPrefix(f.Str(off), "null") {
			return ""
		}
		return f.Str(off)
	}
	for _, line := range lines {
		f.Zero(0x246c, 10)
		f.Zero(0x2484, 10)
		f.Zero(0x2490, 10)
		f.Zero(0x249c, 10)
		f.Sscanf(line, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%s",
			0x2478, 0x2484, 0x2490, 0x249c, 0x24ac, 0x24b4, 0x24bc, 0x25a0, 0x25a8, 0x25b0, 0x25b8, 0x25c0, 0x25c8, 0x25d0, 0x25d8,
			0x2500, 0x2544, 0x2554, 0x25e0, 0x25e8, 0x25f0, 0x25f8, 0x2600, 0x2608, 0x2610, 0x2618, 0x2598)
		row := cemu.Object()
		list.AddItem("", row)
		addCols(row, f, "portNum", 0x2478, "portType", 0x2484, "optionStatusEn", 0x2490, "optionPloyType", 0x249c, "circuitidType", 0x24bc)
		for _, fl := range []struct {
			key string
			off int
		}{{"circuitsysname", 0x25a0}, {"circuitsysmac", 0x25a8}, {"circuitvlanid", 0x25b0}, {"circuitportname", 0x25b8},
			{"circuitontid", 0x25c0}, {"circuitontmac", 0x25c8}, {"circuitontsn", 0x25d0}, {"circuitontmodel", 0x25d8},
			{"remotesysname", 0x25e0}, {"remotesysmac", 0x25e8}, {"remotevlanid", 0x25f0}, {"remoteportname", 0x25f8},
			{"remoteontid", 0x2600}, {"remoteontmac", 0x2608}, {"remoteontsn", 0x2610}, {"remoteontmodel", 0x2618}} {
			row.AddBool(fl.key, strings.HasPrefix(f.Str(fl.off), "1"))
		}
		addCols(row, f, "optionFormat", 0x24ac, "optionDelimiter", 0x24b4)
		row.AddString("circuitiddef", nullDef(0x2500))
		row.AddString("subscriberid", nullDef(0x2544))
		row.AddString("remoteidType", f.Str(0x2554))
		row.AddString("remoteiddef", nullDef(0x2598))
	}
	return root.Print(), nil
}

func init() {
	for _, e := range []*Endpoint{
		{Name: "getAccessList", Handler: "formGetAccessList", fn: getAccessList},
		{Name: "getArpTableList", Handler: "formGetArpTableList", fn: getArpTableList},
		{Name: "getPortTreeStatusList", Handler: "formgetPortTreeStatusList", fn: getPortTreeStatusList},
		{Name: "getIgmpVlanInfo", Handler: "formgetIgmpVlanInfo", fn: getIgmpVlanInfo},
		{Name: "getPortOptical", Handler: "formGetPortOpticalList", fn: getPortOptical},
		{Name: "getSpanningTreeInfo", Handler: "formGetMstpGlobalInfo", fn: getSpanningTreeInfo},
		{Name: "getRadiusInfo", Handler: "formGetRadiusInfo", fn: getRadiusInfo},
		{Name: "getTaskInfo", Handler: "formGetTaskInfo", fn: getTaskInfo},
		{Name: "getServicePort", Handler: "formGetServicePort", fn: getServicePort},
		{Name: "getSnmpNoticeList", Handler: "formGetSnmpNoticeList", fn: getSnmpNoticeList},
		{Name: "getNmsConfigInfo", Handler: "formGetMqttConfigInfo", fn: getNmsConfigInfo},
		{Name: "getMacAddrList", Handler: "formgetMacAddrList", fn: getMacAddrList},
		{Name: "getSystemTimeInfo", Handler: "formGetSystemTimeInfo", fn: getSystemTimeInfo},
		{Name: "getDhcpClientList", Handler: "formgetDhcpClientList", fn: getDhcpClientList},
		{Name: "getDhcpSnoopList", Handler: "formgetDhcpSnoopList", fn: getDhcpSnoopList},
	} {
		e.Op, e.Source = "get", "daemon"
		addPort(e)
	}
}
