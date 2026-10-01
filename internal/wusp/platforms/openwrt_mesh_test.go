package platforms

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"wantastic-agent/internal/wusp"
)

func TestApplyEasyMeshTopologyRestoresGateWhenEnableConfirmationFails(t *testing.T) {
	const liveTopology = `{"topo":[{"mac":"00:03:7F:BA:DB:AD","pMac":"","hops":0,"name":"Controller"}]}`
	const policy = `{"topOptPolicy":"strict","convTimeout":1,"deviceArray":[{"alId":"00:03:7F:BA:DB:AD","parentAlId":"NULL","bStaLinkBand":"6GHL","depth":0,"rssiThresh":-70,"apName":"Controller"}]}`

	setTopoCalled := false
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		UbusParamCaller: func(
			_ context.Context,
			object string,
			method string,
			_ map[string]any,
		) ([]byte, error) {
			if object != "device" {
				return nil, wusp.ErrUSPPathUnsupported
			}
			switch method {
			case "getMode":
				return []byte(`{"mode":"CN"}`), nil
			case "getRealTopo":
				return []byte(liveTopology), nil
			case "setTopo":
				setTopoCalled = true
				return []byte(`{}`), nil
			default:
				return nil, wusp.ErrUSPPathUnsupported
			}
		},
	})
	commands := []easyMeshConsoleCommand{}
	backend.easyMeshConsole = easyMeshConsoleFunc(func(
		_ context.Context,
		command easyMeshConsoleCommand,
	) (string, error) {
		commands = append(commands, command)
		if command == easyMeshConsoleEnableTopologyRequests {
			return "", errors.New("confirmation lost")
		}
		return "ToptReq:Off", nil
	})

	err := backend.ApplyEasyMeshTopology(t.Context(), policy)
	if err == nil || !strings.Contains(err.Error(), "confirmation lost") {
		t.Fatalf("ApplyEasyMeshTopology error=%v", err)
	}
	wantCommands := []easyMeshConsoleCommand{
		easyMeshConsoleEnableTopologyRequests,
		easyMeshConsoleDisableTopologyRequests,
	}
	if !slices.Equal(commands, wantCommands) {
		t.Fatalf("console commands=%v want %v", commands, wantCommands)
	}
	if setTopoCalled {
		t.Fatal("device.setTopo was called without confirmed request gate")
	}
}
