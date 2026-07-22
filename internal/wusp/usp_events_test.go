package wusp

import "testing"

func TestValueChangeEventUsesParentObjectOnWire(t *testing.T) {
	const paramPath = "Device.WUSP_CellularControl.Interface.1.SMSInboxJSON"
	req := EncodeEventToRequest(USPEvent{
		Type:       USPEventTypeValueChange,
		ObjPath:    paramPath,
		ParamValue: `[{"body":"hello"}]`,
	}, 99)

	if req.ObjectPath != "Device.WUSP_CellularControl.Interface.1." {
		t.Fatalf("ObjectPath=%q want parent object", req.ObjectPath)
	}
	if len(req.Paths) != 1 || req.Paths[0] != paramPath {
		t.Fatalf("Paths=%v want changed parameter path", req.Paths)
	}
	if err := validateUSPAgentRequest(req); err != nil {
		t.Fatalf("value-change notify did not validate: %v", err)
	}

	event, err := DecodeEventFromRequest(req)
	if err != nil {
		t.Fatalf("DecodeEventFromRequest: %v", err)
	}
	if event.Type != USPEventTypeValueChange || event.ObjPath != paramPath || event.ParamValue != `[{"body":"hello"}]` {
		t.Fatalf("decoded event=%+v", event)
	}
}
