package endpoints

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/oltd/cemu"
	"wantastic-agent/internal/oltd/wire"
)

// cAtoi is C atoi: optional whitespace and sign, then digits.
func cAtoi(s string) int {
	i := 0
	for i < len(s) && (s[i] == ' ' || (s[i] >= '\t' && s[i] <= '\r')) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	n := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		n = n*10 + int(s[i]-'0')
		i++
	}
	if neg {
		return -n
	}
	return n
}

// ---- getPortBasicList: formGetPortBasicList @0x386a4 --------------------
//
// nsm code 271 (buf 8192) -> one port per line,
//   "name,desc,isolate,status,speed,duplex,fcSend,fcRecv,inlet,outlet,jumbo,bridge,nego"
// pon code 662 (buf 512) -> one PON port per line "status:online:offline".

func getPortBasicList(b Backend, _ Params, _ *Env) ([]byte, error) {
	ports, err := b.Query(SockNSM, simpleMsg(271), 8192)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	pon, err := b.Query(SockPON, simpleMsg(662), 512)
	if err != nil {
		return nil, err
	}
	f := cemu.GetFrame(0x2800)
	defer f.Release()
	for i, line := range cemu.Strtok(pon, "\n") {
		base := 0x2728 - 24*i
		f.Sscanf(line, "%[^:]:%[^:]:%s", base, base-8, base-16)
	}
	if ports == "ERROR" {
		return root.Print(), nil
	}
	num, lines := 1, 0
	for _, line := range cemu.Strtok(ports, "\n") {
		f.Sscanf(line, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%s",
			0x2730, 0x2780, 0x2738, 0x2734, 0x2788, 0x278c, 0x27a0, 0x27a4, 0x27b8, 0x27cc, 0x2794, 0x279c, 0x27d0)
		lines++
		row := cemu.Object()
		list.AddItem("", row)
		f.Write(0x2740, strconv.Itoa(num))
		row.AddString("portNum", f.Str(0x2740))
		row.AddString("portName", f.Str(0x2730))
		row.AddString("desc", f.Str(0x2780))
		row.AddString("portIsolate", f.Str(0x2738))
		if strings.HasPrefix(f.Str(0x2730), "pon") {
			if cAtoi(f.Str(0x2734)) == 0 {
				row.AddString("portStatus", f.Str(0x2734))
			} else if cAtoi(f.Str(0x2728-24*(lines-1))) == 0 {
				row.AddString("portStatus", "2")
			} else {
				row.AddString("portStatus", "1")
			}
		} else {
			row.AddString("portStatus", f.Str(0x2734))
		}
		row.AddString("portSpeed", f.Str(0x2788))
		row.AddString("portDuplex", f.Str(0x278c))
		row.AddString("flowControlSendEn", f.Str(0x27a0))
		row.AddString("flowControlRecvEn", f.Str(0x27a4))
		row.AddString("inletFlow", f.Str(0x27b8))
		row.AddString("portbridge", f.Str(0x279c))
		row.AddString("outletFlow", f.Str(0x27cc))
		row.AddString("jumboFrame", f.Str(0x2794))
		row.AddString("negotiationMode", f.Str(0x27d0))
		num++
	}
	return root.Print(), nil
}

// ---- getQvlanList: formGetVlanList @0x41b84 -----------------------------
//
// nsm code 300 (buf 512 KiB) -> records separated by ':',
//   "vlanId,remark,threeLayersEn,ipType,ip,mask".

func getQvlanList(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockNSM, simpleMsg(300), 524288)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	f := cemu.GetFrame(0x80500)
	defer f.Release()
	for _, rec := range cemu.Strtok(reply, ":") {
		f.Zero(0x80464, 8)
		f.Zero(0x804bc, 33)
		f.Zero(0x80468, 4)
		f.Zero(0x80470, 8)
		f.Zero(0x80484, 20)
		f.Zero(0x80498, 20)
		f.Sscanf(rec, "%[^,],%[^,],%[^,],%[^,],%[^,],%s", 0x80464, 0x804bc, 0x80468, 0x80470, 0x80484, 0x80498)
		row := cemu.Object()
		list.AddItem("", row)
		row.AddString("vlanId", f.Str(0x80464))
		row.AddString("remark", f.Str(0x804bc))
		row.AddString("ip", f.Str(0x80484))
		row.AddString("mask", f.Str(0x80498))
		row.AddString("ipType", f.Str(0x80470))
		row.AddString("threeLayersEn", f.Str(0x80468))
	}
	return root.Print(), nil
}

// ---- getPonPortBasicList: formGetPonPortBasicList @0x76eac ---------------
//
// pon code 661 (buf 2048) -> one PON port per line, ten whitespace
// separated fields.

func getPonPortBasicList(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockPON, simpleMsg(661), 2048)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	if reply == "ERROR" {
		return root.Print(), nil
	}
	f := cemu.GetFrame(0xcc0)
	defer f.Release()
	num := 1
	for _, line := range cemu.Strtok(reply, "\n") {
		f.Sscanf(line, "%s%s%s%s%s%s%s%s%s%s", 0xc70, 0xc74, 0xc88, 0xca4, 0xc78, 0xc90, 0xc94, 0xc9c, 0xca8, 0xcb0)
		row := cemu.Object()
		list.AddItem("", row)
		f.Write(0xc80, strconv.Itoa(num))
		row.AddString("portNum", f.Str(0xc80))
		name := ""
		if num-1 < len(pPortName) {
			name = pPortName[num-1]
		}
		row.AddString("portName", name)
		row.AddString("portstate", f.Str(0xc88))
		row.AddString("portStatus", f.Str(0xc74))
		row.AddString("p2p", f.Str(0xc78))
		row.AddString("autoauth", f.Str(0xc90))
		row.AddString("authmode", f.Str(0xc94))
		row.AddString("loopdetect", f.Str(0xc9c))
		row.AddString("autofind", f.Str(0xca4))
		row.AddString("loopbackshutdown", f.Str(0xca8))
		row.AddString("powerlimit", f.Str(0xcb0))
		num++
	}
	return root.Print(), nil
}

// ---- getSysStatus: formGetSysStatus @0x31a14 -----------------------------
//
// Local part (webserver process): sysTime (localtime), runTime
// (sysinfo.uptime), cpuPercent (libfos pal_get_cpu_usage, /proc/stat),
// memoryPercent (/proc/meminfo), temp1/temp2 (i2c LM75 0x48/0x4a/0x49 on
// bus 1), power1/power2 (i2c 0x53), fan1-3 (constant strings),
// pon_not_start (/mnt/config/running_time.cfg), DNS (/etc/resolv.conf).
// Daemon part: um 156 (versions), um 157 (name/mac/sn), nsm 417
// (location), um 419 (temp thresholds), nsm 387 "mng0" (mgmt ip), nsm 386
// (gateway), nsm 272 + pon 662 (port table).

const fanString = "WORK     RPM: 6600"

func getSysStatus(b Backend, _ Params, env *Env) ([]byte, error) {
	root := cemu.Object()
	var unsupported []string

	root.AddString("sysTime", localTimeString(env, time.Now()))
	if up, ok := uptimeSeconds(); ok {
		root.AddString("runTime", strconv.FormatInt(up, 10))
	} else {
		root.AddString("runTime", "0")
	}
	root.AddString("cpuPercent", strconv.FormatUint(uint64(cpuPercent(env)), 10)+"%")
	root.AddString("memoryPercent", memoryPercent(env)+"%")

	if t1, t2, ok := boardTemps(env); ok {
		root.AddString("temp1value", strconv.FormatFloat(float64(t1)/10.0, 'f', 1, 64))
		root.AddString("temp2value", strconv.FormatFloat(float64(t2)/10.0, 'f', 1, 64))
	} else {
		unsupported = append(unsupported, "temp1value", "temp2value")
	}
	// power_state_get reads i2c 0x53 on a bus taken from a stale register in
	// the vendor code; not reproduced natively.
	unsupported = append(unsupported, "power1", "power2")
	root.AddString("fan1", fanString)
	root.AddString("fan2", fanString)
	root.AddString("fan3", fanString)

	f := cemu.GetFrame(0x1f70)
	defer f.Release()

	// Every daemon sub-call degrades on its own: a failure drops only the
	// fields it feeds (listed in _helperUnsupported). After a timeout the
	// remaining calls to the same socket are skipped (no 5 s per field).
	// Only when every daemon call fails does the endpoint fail.
	dead := map[string]bool{}
	calls, okCalls := 0, 0
	q := func(sock string, build func(string) (wire.Msg, error), buf int, fields ...string) (string, bool) {
		calls++
		if dead[sock] {
			unsupported = append(unsupported, fields...)
			return "", false
		}
		reply, err := b.Query(sock, build, buf)
		if err != nil {
			if isTimeout(err) {
				dead[sock] = true
			}
			unsupported = append(unsupported, fields...)
			return "", false
		}
		okCalls++
		return reply, true
	}

	if ver, ok := q(SockUM, simpleMsg(156), 2048, "softwareVersion", "hardwareVersion", "created", "productOid"); ok {
		toks := cemu.Strtok(ver, ",")
		f.Zero(0xde0, 64)
		f.Zero(0xda0, 16)
		f.Zero(0xe20, 64)
		f.Zero(0xea0, 128)
		for i, dst := range []struct{ off, n int }{{0xde0, 63}, {0xda0, 15}, {0xe20, 63}, {0xea0, 127}} {
			if i < len(toks) {
				f.Strncpy(dst.off, toks[i], dst.n)
			}
		}
		root.AddString("softwareVersion", f.Str(0xde0))
		root.AddString("hardwareVersion", f.Str(0xda0))
		root.AddString("created", f.Str(0xe20))
		root.AddString("productOid", f.Str(0xea0))
	}

	if dev, ok := q(SockUM, simpleMsg(157), 2048, "deviceName", "mac", "sn"); ok {
		f.Sscanf(dev, "%[^,],%[^,],%[^,],%s", 0xce8, 0xd68, 0xd7c, 0xd90)
		root.AddString("deviceName", f.Str(0xce8))
		root.AddString("mac", f.Str(0xd7c))
		root.AddString("sn", f.Str(0xd90))
	}

	if loc, ok := q(SockNSM, simpleMsg(417), 2048, "deviceLocation"); ok {
		if loc != "" {
			root.AddString("deviceLocation", base64.StdEncoding.EncodeToString([]byte(loc)))
		} else {
			root.AddString("deviceLocation", "")
		}
	}

	if thr, ok := q(SockUM, simpleMsg(419), 2048, "temphi", "templo"); ok {
		f.Sscanf(thr, "%[^,],%s", 0x16f0, 0x16f8)
		root.AddString("temphi", f.Str(0x16f0))
		root.AddString("templo", f.Str(0x16f8))
	}

	if raw, ok := readFile(env, "/mnt/config/running_time.cfg", 16); ok {
		buf := make([]byte, 16)
		copy(buf, raw)
		root.AddNumber("pon_not_start", float64(binary.LittleEndian.Uint32(buf[8:])))
	} else {
		root.AddNumber("pon_not_start", 0)
	}

	root.AddString("dnsType", "manual")
	addDNS(root, env)

	if mng, ok := q(SockNSM, func(path string) (wire.Msg, error) {
		m, err := wire.NewMsg(387, path)
		if err != nil {
			return nil, err
		}
		m.PutU16(34, 4)
		m.PutString(58, "mng0")
		return m, nil
	}, 2048, "ip", "mask", "ipType"); ok {
		f.Sscanf(mng, "%[^,],%[^,],%s", 0x1edc, 0x1eec, 0x1f0c)
		root.AddString("ip", f.Str(0x1edc))
		root.AddString("mask", f.Str(0x1eec))
		root.AddString("ipType", f.Str(0x1f0c))
	}

	if gw, ok := q(SockNSM, func(path string) (wire.Msg, error) {
		m, err := wire.NewMsg(386, path)
		if err != nil {
			return nil, err
		}
		m.PutString(58, "0.0.0.0")
		m.PutU16(34, 7)
		return m, nil
	}, 2048, "gateway"); ok {
		f.Sscanf(gw, "%s", 0x1efc)
		if f.Str(0x1efc) == "1" {
			root.AddString("gateway", "")
		} else {
			root.AddString("gateway", f.Str(0x1efc))
		}
	}

	ports, portsOK := q(SockNSM, simpleMsg(272), 2048, "port")
	pon, _ := q(SockPON, simpleMsg(662), 512, "port.ponStatus")
	if portsOK {
		portArr := cemu.Array()
		root.AddItem("port", portArr)
		for i, line := range cemu.Strtok(pon, "\n") {
			base := 0x1eb8 - 24*i
			f.Sscanf(line, "%[^:]:%[^:]:%s", base, base-8, base-16)
		}
		n := 0
		for _, line := range cemu.Strtok(ports, "\n") {
			f.Zero(0x1f14, 8)
			f.Zero(0x1f20, 8)
			n++
			f.Sscanf(line, "%[^;];%[^;];%[^;];%[^;];%[^;];%s", 0x1f14, 0x1f50, 0x1f18, 0x1f28, 0x1f2c, 0x1f58)
			f.Write(0x1f20, strconv.Itoa(n))
			row := cemu.Object()
			portArr.AddItem("", row)
			row.AddString("portNum", f.Str(0x1f20))
			row.AddString("portName", f.Str(0x1f14))
			row.AddString("portDesc", f.Str(0x1f50))
			row.AddString("portDuplex", f.Str(0x1f2c))
			row.AddString("portSpeed", f.Str(0x1f28))
			isPon := strings.HasPrefix(f.Str(0x1f14), "pon")
			ponBase := 0x1eb8 - 24*(n-1)
			if isPon {
				row.AddString("portStatus", f.Str(ponBase))
			} else if cAtoi(f.Str(0x1f18)) == 1 {
				row.AddString("portStatus", "1")
			} else {
				row.AddString("portStatus", "0")
			}
			row.AddString("negotiationMode", f.Str(0x1f58))
			if isPon {
				row.AddString("online", f.Str(ponBase-8))
				row.AddString("offline", f.Str(ponBase-16))
			}
			row.AddString("poeEn", "2")
		}
	}
	if okCalls == 0 {
		return nil, fmt.Errorf("getSysStatus: all %d daemon sub-requests failed", calls)
	}
	if len(unsupported) > 0 {
		arr := cemu.Array()
		for _, k := range unsupported {
			arr.AddString("", k)
		}
		root.AddItem("_helperUnsupported", arr)
	}
	return root.Print(), nil
}

// addDNS reproduces the /etc/resolv.conf scan, including the vendor's
// duplicate keys (every nameserver after the first adds another
// "alternateDNS"; an empty file adds the 0.0.0.0 pair twice).
func addDNS(root *cemu.JSON, env *Env) {
	count := 0
	if raw, ok := readFile(env, "/etc/resolv.conf", 64<<10); ok {
		for _, line := range fgetsLines(string(raw), 64) {
			if !strings.Contains(line, "nameserver") {
				continue
			}
			var ip string
			cemu.Sscanf(line, "%s %s", func(i int, v string) {
				if i == 1 {
					ip = v
				}
			})
			if count == 0 {
				root.AddString("preferredDNS", ip)
			} else {
				root.AddString("alternateDNS", ip)
			}
			count++
		}
		if count == 0 {
			root.AddString("preferredDNS", "0.0.0.0")
			root.AddString("alternateDNS", "0.0.0.0")
		}
	}
	if count == 1 {
		root.AddString("alternateDNS", "0.0.0.0")
	}
	if count == 0 {
		root.AddString("preferredDNS", "0.0.0.0")
		root.AddString("alternateDNS", "0.0.0.0")
	}
}

// fgetsLines splits like repeated fgets(buf, size, f): at most size-1 bytes
// per read, a read ends after '\n'.
func fgetsLines(s string, size int) []string {
	var out []string
	for len(s) > 0 {
		n := 0
		for n < len(s) && n < size-1 {
			n++
			if s[n-1] == '\n' {
				break
			}
		}
		out = append(out, s[:n])
		s = s[n:]
	}
	return out
}
