package endpoints

import (
	"encoding/base64"
	"strings"

	"wantastic-agent/internal/oltd/cemu"
	"wantastic-agent/internal/oltd/sysx"
)

// Second batch of hand-ported getters (see ports_getters.go for the
// conventions).

// oneField runs a getter whose reply is one line scanned into one buffer:
// sscanf(reply, fmt, buf) then {key: buf}. Replies containing "error"
// answer errCode 101 when errorCheck is set.
func oneField(sock string, code uint16, buf int, errorCheck bool, fmt, key string) func(Backend, Params, *Env) ([]byte, error) {
	return func(b Backend, _ Params, _ *Env) ([]byte, error) {
		reply, err := b.Query(sock, simpleMsg(code), buf)
		if err != nil {
			return nil, err
		}
		if errorCheck && strings.Contains(reply, "error") {
			return errCodeJSON(101), nil
		}
		f := cemu.GetFrame(0x40)
		defer f.Release()
		if fmt != "" {
			f.Sscanf(reply, fmt, 0x20)
		} else {
			f.Write(0x20, reply)
		}
		root := cemu.Object()
		root.AddString(key, f.Str(0x20))
		return root.Print(), nil
	}
}

// ---- getCosPriorityInfo: formGetCosPriorityInfo @0x661b8 -----------------
//
// nsm 344 (buf 128) -> eight whitespace separated values into eight
// adjacent 4-byte buffers, printed as the "cosPriority" array.

func getCosPriorityInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockNSM, simpleMsg(344), 128)
	if err != nil {
		return nil, err
	}
	f := cemu.GetFrame(0x500)
	defer f.Release()
	f.Sscanf(reply, "%s%s%s%s%s%s%s%s", 0x4f0, 0x4ec, 0x4e8, 0x4e4, 0x4e0, 0x4dc, 0x4d8, 0x4d4)
	root := cemu.Object()
	arr := cemu.Array()
	root.AddItem("cosPriority", arr)
	for i := 0; i <= 7; i++ {
		arr.AddString("", f.Str(0x4f0-4*i))
	}
	return root.Print(), nil
}

// ---- getDscpQueueInfo: formGetDscpQueueInfo @0x66bbc ---------------------
//
// nsm 346 (buf 512): "finish" means disabled (dscpEn "0", no queues);
// otherwise 64 entries are read with sscanf("%s") from every second byte
// of the reply into a 4-byte buffer placed right below the reply buffer.

func getDscpQueueInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockNSM, simpleMsg(346), 512)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	arr := cemu.Array()
	root.AddItem("dscpQueue", arr)
	if reply == "finish" {
		root.AddString("dscpEn", "0")
		return root.Print(), nil
	}
	root.AddString("dscpEn", "1")
	f := cemu.GetFrame(0x660)
	defer f.Release()
	f.Write(0x650, reply)
	for i := 0; i <= 63; i++ {
		f.Sscanf(f.Str(0x650-2*i), "%s", 0x654)
		arr.AddString("", f.Str(0x654))
	}
	return root.Print(), nil
}

// ---- getQoSScheduleInfo: formGetQoSScheduleInfo @0x65180 -----------------
//
// nsm 338 (buf 128) -> "mode w1 .. w8"; the eight weights are listed only
// for a WRR mode.

func getQoSScheduleInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockNSM, simpleMsg(338), 128)
	if err != nil {
		return nil, err
	}
	f := cemu.GetFrame(0x500)
	defer f.Release()
	f.Sscanf(reply, "%s", 0x4f8)
	root := cemu.Object()
	arr := cemu.Array()
	root.AddItem("qosQueue", arr)
	if strings.Contains(f.Str(0x4f8), "WRR") {
		f.Sscanf(reply, "%s%s%s%s%s%s%s%s%s", 0x4f8, 0x4f0, 0x4ec, 0x4e8, 0x4e4, 0x4e0, 0x4dc, 0x4d8, 0x4d4)
		for i := 0; i <= 7; i++ {
			arr.AddString("", f.Str(0x4f0-4*i))
		}
	}
	root.AddString("qosMode", f.Str(0x4f8))
	return root.Print(), nil
}

// ---- getQinqVlanList / getVlanTransformList ------------------------------
//
// formGetQinqVlanList @0x691c8 (nsm 434) and formGetVlanTransformList
// @0x67a84 (nsm 430), buf 4096: one rule per line
// "portName,startvlan,endvlan,destvlan" with a numeric running index. The
// buffers are zeroed once (getQinqVlanList starts endvlan with a 0x10 byte).

func vlanRangeList(code uint16, endvlanInit string) func(Backend, Params, *Env) ([]byte, error) {
	return func(b Backend, _ Params, _ *Env) ([]byte, error) {
		reply, err := b.Query(SockNSM, simpleMsg(code), 4096)
		if err != nil {
			return nil, err
		}
		root := cemu.Object()
		list := cemu.Array()
		root.AddItem("list", list)
		f := cemu.GetFrame(0x1490)
		defer f.Release()
		f.Write(0x1480, endvlanInit)
		n := 0
		for _, line := range cemu.Strtok(reply, "\n") {
			f.Sscanf(line, "%[^,],%[^,],%[^,],%s", 0x1488, 0x1468, 0x1480, 0x1478)
			row := cemu.Object()
			list.AddItem("", row)
			n++
			row.AddNumber("index", float64(n))
			addCols(row, f, "portName", 0x1488, "startvlan", 0x1468, "endvlan", 0x1480, "destvlan", 0x1478)
		}
		return root.Print(), nil
	}
}

// ---- getAuthGlobalInfo: formGetAuthGlobalInfo @0x69fb4 -------------------
//
// authd 464 (buf 256) -> "authIp shareKey".

func getAuthGlobalInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockAUTHD, simpleMsg(464), 256)
	if err != nil {
		return nil, err
	}
	f := cemu.GetFrame(0x1a0)
	defer f.Release()
	f.Sscanf(reply, "%s %s", 0x190, 0x150)
	root := cemu.Object()
	addCols(root, f, "authIp", 0x190, "shareKey", 0x150)
	return root.Print(), nil
}

// ---- getSnmpBasicInfo: formGetSnmpBasicInfo @0x6c78c ---------------------
//
// um 397 (buf 1024) -> contact, um 417 (buf 1024) -> location; the first
// word of each reply is base64 encoded.

func getSnmpBasicInfo(b Backend, _ Params, _ *Env) ([]byte, error) {
	root := cemu.Object()
	f := cemu.GetFrame(0x1110)
	defer f.Release()
	for _, q := range []struct {
		code uint16
		off  int
		key  string
	}{{397, 0xcc8, "contactInfo"}, {417, 0x10c8, "locationInfo"}} {
		reply, err := b.Query(SockUM, simpleMsg(q.code), 1024)
		if err != nil {
			return nil, err
		}
		f.Sscanf(reply, " %s", q.off)
		root.AddString(q.key, base64.StdEncoding.EncodeToString([]byte(f.Str(q.off))))
	}
	return root.Print(), nil
}

// ---- getSnmpAccessList: formGetSnmpAccessList @0x6cd04 -------------------
//
// um 398 (buf 2048) -> one community per line
// "communityName accessRule mibView" ("--" prints as "").

func getSnmpAccessList(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockUM, simpleMsg(398), 2048)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("communityList", list)
	f := cemu.GetFrame(0xcc0)
	defer f.Release()
	for _, line := range cemu.Strtok(reply, "\n") {
		row := cemu.Object()
		list.AddItem("", row)
		f.Zero(0xcb0, 33)
		f.Zero(0xc68, 16)
		f.Zero(0xc8c, 33)
		f.Sscanf(line, "%s%s%s", 0xcb0, 0xc68, 0xc8c)
		addCols(row, f, "communityName", 0xcb0, "accessRule", 0xc68)
		view := f.Str(0xc8c)
		if strings.HasPrefix(view, "--") {
			view = ""
		}
		row.AddString("mibView", view)
	}
	return root.Print(), nil
}

// ---- getPortSecurity: formgetPortSecurity @0x500d8 -----------------------
//
// nsm 440 (buf 16384) -> one port per line "portName,flapping,limit";
// portNum is a numeric running index.

func getPortSecurity(b Backend, _ Params, _ *Env) ([]byte, error) {
	reply, err := b.Query(SockNSM, simpleMsg(440), 16384)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	f := cemu.GetFrame(0x44a0)
	defer f.Release()
	n := 0
	for _, line := range cemu.Strtok(reply, "\n") {
		f.Zero(0x4464, 10)
		f.Zero(0x448c, 25)
		f.Sscanf(line, "%[^,],%[^,],%s", 0x448c, 0x4464, 0x4470)
		row := cemu.Object()
		list.AddItem("", row)
		n++
		row.AddNumber("portNum", float64(n))
		addCols(row, f, "portName", 0x448c, "flapping", 0x4464, "limit", 0x4470)
	}
	return root.Print(), nil
}

// ---- getMstpInstanceList: formGetMstpInstanceList @0x51da0 ---------------
//
// usleep(100 ms), then mstp 572 (buf 16384) -> one instance per line
// "instanceId bridgePriority vlanList"; a vlanList with a space loses its
// last character (strrchr/strncpy, unreachable after %s).

func getMstpInstanceList(b Backend, _ Params, _ *Env) ([]byte, error) {
	sysx.Sleep(100_000_000)
	reply, err := b.Query(SockMSTP, simpleMsg(572), 16384)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	list := cemu.Array()
	root.AddItem("list", list)
	f := cemu.GetFrame(0x4470)
	defer f.Release()
	for _, line := range cemu.Strtok(reply, "\n") {
		f.Zero(0x4460, 8)
		f.Zero(0x4468, 8)
		vlan := ""
		cemu.Sscanf(line, "%s %s %s", func(i int, v string) {
			switch i {
			case 0:
				f.Write(0x4468, v)
			case 1:
				f.Write(0x4460, v)
			case 2:
				vlan = v
			}
		})
		if strings.Contains(vlan, " ") {
			vlan = vlan[:len(vlan)-1]
		}
		row := cemu.Object()
		list.AddItem("", row)
		row.AddString("instanceId", f.Str(0x4468))
		row.AddString("statusEn", "1")
		row.AddString("vlanList", vlan)
		row.AddString("bridgePriority", f.Str(0x4460))
	}
	return root.Print(), nil
}

// ---- getVerifyCode: formGetVerifyCode @0x344f0 ---------------------------
//
// um 182 (buf 128) -> isShowverify = atoi(reply) != 0; nsm 421 (buf 128)
// -> "telnet,ssh,http,https,snmp" enables as booleans.

func getVerifyCode(b Backend, _ Params, _ *Env) ([]byte, error) {
	show, err := b.Query(SockUM, simpleMsg(182), 128)
	if err != nil {
		return nil, err
	}
	root := cemu.Object()
	root.AddBool("isShowverify", cAtoi(show) != 0)
	svc, err := b.Query(SockNSM, simpleMsg(421), 128)
	if err != nil {
		return nil, err
	}
	f := cemu.GetFrame(0x500)
	defer f.Release()
	f.Sscanf(svc, "%[^,],%[^,],%[^,],%[^,],%s", 0x4d0, 0x4d8, 0x4e0, 0x4e8, 0x4f0)
	for _, c := range []struct {
		key string
		off int
	}{{"telnetEn", 0x4d0}, {"sshEn", 0x4d8}, {"httpEn", 0x4e0}, {"httpsEn", 0x4e8}, {"snmpEn", 0x4f0}} {
		root.AddBool(c.key, cAtoi(f.Str(c.off)) != 0)
	}
	return root.Print(), nil
}

// ---- multicast tables: formgetMulGroupList @0x59f6c (nsm 90),
// formgetMulRouterTab @0x5a82c (nsm 97), formgetMulRouterPort @0x5a2fc
// (nsm 99); 32 KiB malloc'd reply buffer, comma separated columns, the
// column buffers zeroed once.

func mulTable(code uint16, fmt string, offs []int, cols ...any) func(Backend, Params, *Env) ([]byte, error) {
	return func(b Backend, _ Params, _ *Env) ([]byte, error) {
		reply, err := b.Query(SockNSM, simpleMsg(code), 32768)
		if err != nil {
			return nil, err
		}
		root := cemu.Object()
		list := cemu.Array()
		root.AddItem("list", list)
		f := cemu.GetFrame(0x44a0)
		defer f.Release()
		for _, line := range cemu.Strtok(reply, "\n") {
			f.Sscanf(line, fmt, offs...)
			row := cemu.Object()
			list.AddItem("", row)
			addCols(row, f, cols...)
		}
		return root.Print(), nil
	}
}

func init() {
	for _, e := range []*Endpoint{
		{Name: "getCosPriorityInfo", Handler: "formGetCosPriorityInfo", fn: getCosPriorityInfo},
		{Name: "getDscpQueueInfo", Handler: "formGetDscpQueueInfo", fn: getDscpQueueInfo},
		{Name: "getQoSScheduleInfo", Handler: "formGetQoSScheduleInfo", fn: getQoSScheduleInfo},
		{Name: "getQinqVlanList", Handler: "formGetQinqVlanList", fn: vlanRangeList(434, "\x10")},
		{Name: "getVlanTransformList", Handler: "formGetVlanTransformList", fn: vlanRangeList(430, "")},
		// formgetPortArpAttackInfo @0x46838: nsm 298 (buf 128), "error" -> 101, first word.
		{Name: "getPortArpAttackInfo", Handler: "formgetPortArpAttackInfo", fn: oneField(SockNSM, 298, 128, true, "%s", "arpReceptRate")},
		// formgetIgmpSnoopEn @0x57f98: nsm 73 (buf 128), first word.
		{Name: "getIgmpSnoopEn", Handler: "formgetIgmpSnoopEn", fn: oneField(SockNSM, 73, 128, false, "%s", "igmpSnoopingEn")},
		// formGetNetAuthEn @0x69d2c: authd 461 (buf 32), raw reply.
		{Name: "getNetAuthEn", Handler: "formGetNetAuthEn", fn: oneField(SockAUTHD, 461, 32, false, "", "authEn")},
		{Name: "getAuthGlobalInfo", Handler: "formGetAuthGlobalInfo", fn: getAuthGlobalInfo},
		{Name: "getSnmpBasicInfo", Handler: "formGetSnmpBasicInfo", fn: getSnmpBasicInfo},
		{Name: "getSnmpAccessList", Handler: "formGetSnmpAccessList", fn: getSnmpAccessList},
		{Name: "getPortSecurity", Handler: "formgetPortSecurity", fn: getPortSecurity},
		{Name: "getMstpInstanceList", Handler: "formGetMstpInstanceList", fn: getMstpInstanceList},
		{Name: "getVerifyCode", Handler: "formGetVerifyCode", fn: getVerifyCode},
		{Name: "getMulGroupList", Handler: "formgetMulGroupList", fn: mulTable(90, "%[^,],%[^,],%[^,],", []int{0x47c, 0x449c, 0x447c}, "portNum", 0x449c, "vlanid", 0x47c, "groups", 0x447c)},
		{Name: "getMulRouterTab", Handler: "formgetMulRouterTab", fn: mulTable(97, "%[^,],%[^,],", []int{0x47c, 0x49c}, "vlanId", 0x47c, "port", 0x49c)},
		{Name: "getMulrouterList", Handler: "formgetMulRouterPort", fn: mulTable(99, "%[^,],%[^,],", []int{0x47c, 0x49c}, "vlanid", 0x47c, "portNum", 0x49c)},
	} {
		e.Op, e.Source = "get", "daemon"
		addPort(e)
	}
}
