package wusp

import "testing"

func TestWUSPCellularSMSOperationInputsValidate(t *testing.T) {
	prefix := "Device.WUSP_CellularControl.Interface.1.SMS."
	msg := NewMessage()
	msg.Set(prefix+"PhoneNumber", String("+212709251456"))
	msg.Set(prefix+"Message", String("test message"))
	msg.Set(prefix+"DeleteIndex", String("all"))

	if err := ValidateMessageFast(msg); err != nil {
		t.Fatalf("ValidateMessageFast(SMS operation inputs) error: %v", err)
	}
}
