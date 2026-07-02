//go:build linux

package modem

import "testing"

func TestParseQuectelServingCellLTE(t *testing.T) {
	info := &Info{}
	c := &atController{}

	c.parseQuectelServingCellInfo([]string{
		`+QENG: "servingcell","NOCONN","LTE","FDD",460,01,1A2B3C4,123,100,1,5,5,1E7F,-97,-8,-68,15,42`,
	}, info)

	if info.Technology != TechLTE {
		t.Fatalf("Technology=%v want LTE", info.Technology)
	}
	if info.OperatorMCC != "460" || info.OperatorMNC != "01" {
		t.Fatalf("operator=%s/%s want 460/01", info.OperatorMCC, info.OperatorMNC)
	}
	if info.CellID != 0x1A2B3C4 {
		t.Fatalf("CellID=%x want 1A2B3C4", info.CellID)
	}
	if info.TAC != 0x1E7F {
		t.Fatalf("TAC=%x want 1E7F", info.TAC)
	}
	if info.Signal.RSRP != -97 || info.Signal.RSRQ != -8 || info.Signal.RSSI != -68 || info.Signal.SINR != 15 {
		t.Fatalf("signal=%+v", info.Signal)
	}
}

func TestParseQuectelNetworkInfo(t *testing.T) {
	info := &Info{}
	c := &atController{}

	c.parseQuectelNetworkInfo(`+QNWINFO: "FDD LTE","310410","LTE BAND 2",800`, info)

	if info.Technology != TechLTE {
		t.Fatalf("Technology=%v want LTE", info.Technology)
	}
	if info.OperatorMCC != "310" || info.OperatorMNC != "410" {
		t.Fatalf("operator=%s/%s want 310/410", info.OperatorMCC, info.OperatorMNC)
	}
	if info.Band != "800" {
		t.Fatalf("Band=%q want 800", info.Band)
	}
}

func TestParseFibocomXCESQ(t *testing.T) {
	c := &atController{}
	sig := SignalQuality{}

	c.parseFibocomXCESQ("+XCESQ: 99,99,255,255,30,50", &sig)

	if sig.RSRQ != -4 || sig.RSRP != -90 {
		t.Fatalf("signal=%+v want RSRQ=-4 RSRP=-90", sig)
	}
}

func TestParseJSONSignalUQMI(t *testing.T) {
	info := &Info{}

	parseJSONSignal([]byte(`{"type":"lte","rssi":-61,"rsrq":-8,"rsrp":-91,"snr":16}`), info)

	if info.Technology != TechLTE {
		t.Fatalf("Technology=%v want LTE", info.Technology)
	}
	if info.Signal.RSSI != -61 || info.Signal.RSRQ != -8 || info.Signal.RSRP != -91 || info.Signal.SINR != 16 {
		t.Fatalf("signal=%+v", info.Signal)
	}
}
