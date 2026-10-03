package platforms

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"wantastic-agent/internal/wusp"
)

func TestApplyEasyMeshTopologyStopsWhenOptimizerDisableConfirmationFails(t *testing.T) {
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
	disableAttempts := 0
	backend.easyMeshConsole = easyMeshConsoleFunc(func(
		_ context.Context,
		command easyMeshConsoleCommand,
	) (string, error) {
		commands = append(commands, command)
		disableAttempts++
		if disableAttempts == 1 {
			return "", errors.New("confirmation lost")
		}
		return "ToptReq:Off", nil
	})

	err := backend.ApplyEasyMeshTopology(t.Context(), policy)
	if err == nil || !strings.Contains(err.Error(), "confirmation lost") {
		t.Fatalf("ApplyEasyMeshTopology error=%v", err)
	}
	wantCommands := []easyMeshConsoleCommand{
		easyMeshConsoleDisableTopologyRequests,
		easyMeshConsoleDisableTopologyRequests,
	}
	if !slices.Equal(commands, wantCommands) {
		t.Fatalf("console commands=%v want %v", commands, wantCommands)
	}
	if setTopoCalled {
		t.Fatal("device.setTopo was called without confirmed request gate")
	}
}

func TestApplyEasyMeshTopologyRejectsMismatchedDeviceReadback(t *testing.T) {
	const liveTopology = `{"topo":[{"mac":"00:03:7F:BA:DB:AD","pMac":"","hops":0,"name":"Controller"}]}`
	const requestedPolicy = `{"topOptPolicy":"strict","convTimeout":120,"deviceArray":[{"alId":"00:03:7F:BA:DB:AD","parentAlId":"NULL","bStaLinkBand":"6GHL","depth":0,"rssiThresh":-70,"apName":"Controller"}]}`
	const savedPolicy = `{"topOptPolicy":"strict","convTimeout":119,"deviceArray":[{"alId":"00:03:7F:BA:DB:AD","parentAlId":"NULL","bStaLinkBand":"6GHL","depth":0,"rssiThresh":-70,"apName":"Controller"}]}`

	events := []string{}
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
			case "getTopo":
				return []byte(savedPolicy), nil
			case "setTopo":
				events = append(events, "setTopo")
				return []byte(`{}`), nil
			default:
				return nil, wusp.ErrUSPPathUnsupported
			}
		},
	})
	backend.easyMeshConsole = easyMeshConsoleFunc(func(
		_ context.Context,
		command easyMeshConsoleCommand,
	) (string, error) {
		if command == easyMeshConsoleEnableTopologyRequests {
			events = append(events, "enable")
			return "ToptReq:ON", nil
		}
		events = append(events, "disable")
		return "ToptReq:Off", nil
	})

	err := backend.ApplyEasyMeshTopology(t.Context(), requestedPolicy)
	if err == nil || !strings.Contains(
		err.Error(),
		"requested convTimeout=120, device.getTopo reports convTimeout=119",
	) {
		t.Fatalf("ApplyEasyMeshTopology error=%v", err)
	}
	if !slices.Equal(events, []string{"disable", "setTopo", "disable"}) {
		t.Fatalf("EasyMesh control events=%v", events)
	}
}

func TestApplyEasyMeshControllerDefaultsUsesVendorManagedBand(t *testing.T) {
	topology := easyMeshTopology{
		TopOptPolicy: "permissive",
		ConvTimeout:  120,
		DeviceArray: []easyMeshTopologyNode{
			{ALID: "00:03:7F:BA:DB:AD", ParentALID: "NULL", BStaLinkBand: "6GH", Depth: 0, RSSIThreshold: -50},
			{ALID: "E0:5D:54:4B:E6:CF", ParentALID: "00:03:7F:BA:DB:AD", BStaLinkBand: "6GHL", Depth: 1, RSSIThreshold: -80},
			{ALID: "E0:5D:54:4B:E5:DC", ParentALID: "E0:5D:54:4B:E6:CF", BStaLinkBand: "6GH", Depth: 2, RSSIThreshold: -90},
		},
	}

	normalized, err := applyEasyMeshControllerDefaults(&topology)
	if err != nil {
		t.Fatalf("applyEasyMeshControllerDefaults: %v", err)
	}
	if topology.TopOptPolicy != "strict" || topology.ConvTimeout != 120 {
		t.Fatalf("controller defaults=%+v", topology)
	}
	for index, node := range topology.DeviceArray {
		if node.BStaLinkBand != "6GHL" || node.RSSIThreshold != -70 {
			t.Fatalf("deviceArray[%d]=%+v", index, node)
		}
	}
	if !strings.Contains(normalized, `"convTimeout":120`) ||
		strings.Contains(normalized, `"bStaLinkBand":"6GL"`) ||
		strings.Contains(normalized, `"bStaLinkBand":"6GH"`) {
		t.Fatalf("normalized topology=%s", normalized)
	}
}

func TestApplyEasyMeshTopologyAcceptsPersistedPlanAcrossConsoleRestart(t *testing.T) {
	const liveTopology = `{"topo":[{"mac":"00:03:7F:BA:DB:AD","pMac":"","hops":0,"name":"Controller"}]}`
	const requestedPolicy = `{"topOptPolicy":"permissive","convTimeout":120,"deviceArray":[{"alId":"00:03:7F:BA:DB:AD","parentAlId":"NULL","bStaLinkBand":"6GH","depth":0,"rssiThresh":-50,"apName":"Controller"}]}`

	savedPolicy := ""
	disableAttempts := 0
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		EasyMeshVerifyInterval: time.Millisecond,
		EasyMeshStableDuration: 2 * time.Millisecond,
		UbusParamCaller: func(
			_ context.Context,
			object string,
			method string,
			params map[string]any,
		) ([]byte, error) {
			if object != "device" {
				return nil, wusp.ErrUSPPathUnsupported
			}
			switch method {
			case "getMode":
				return []byte(`{"mode":"CN"}`), nil
			case "getRealTopo":
				return []byte(liveTopology), nil
			case "getTopo":
				return []byte(savedPolicy), nil
			case "setTopo":
				savedPolicy, _ = params["data"].(string)
				return nil, errors.New("vendor console restarted")
			default:
				return nil, wusp.ErrUSPPathUnsupported
			}
		},
	})
	backend.easyMeshConsole = easyMeshConsoleFunc(func(
		_ context.Context,
		command easyMeshConsoleCommand,
	) (string, error) {
		if command == easyMeshConsoleEnableTopologyRequests {
			return "ToptReq:ON", nil
		}
		disableAttempts++
		if disableAttempts == 2 {
			return "", errors.New("connection refused")
		}
		return "ToptReq:Off", nil
	})

	if err := backend.ApplyEasyMeshTopology(t.Context(), requestedPolicy); err != nil {
		t.Fatalf("ApplyEasyMeshTopology: %v", err)
	}
	if disableAttempts != 3 {
		t.Fatalf("disable attempts=%d want 3", disableAttempts)
	}
	if !strings.Contains(savedPolicy, `"topOptPolicy":"strict"`) ||
		!strings.Contains(savedPolicy, `"convTimeout":120`) {
		t.Fatalf("saved policy=%s", savedPolicy)
	}
}

func TestApplyEasyMeshTopologyRejectsRelayWithoutBackhaulBSS(t *testing.T) {
	const starTopology = `{"topo":[{"mac":"00:03:7F:BA:DB:AD","pMac":"","hops":0,"name":"Controller"},{"mac":"E0:5D:54:4B:E6:CF","pMac":"00:03:7F:BA:DB:AD","hops":1,"name":"Relay A"},{"mac":"E0:5D:54:4B:E5:DC","pMac":"00:03:7F:BA:DB:AD","hops":1,"name":"Relay B"}]}`
	const requestedPolicy = `{"topOptPolicy":"strict","convTimeout":1,"deviceArray":[{"alId":"00:03:7F:BA:DB:AD","parentAlId":"NULL","bStaLinkBand":"6GHL","depth":0,"rssiThresh":-70,"apName":"Controller"},{"alId":"E0:5D:54:4B:E6:CF","parentAlId":"00:03:7F:BA:DB:AD","bStaLinkBand":"6GHL","depth":1,"rssiThresh":-70,"apName":"Relay A"},{"alId":"E0:5D:54:4B:E5:DC","parentAlId":"E0:5D:54:4B:E6:CF","bStaLinkBand":"6GHL","depth":2,"rssiThresh":-70,"apName":"Relay B"}]}`

	requested := easyMeshTopology{}
	if err := json.Unmarshal([]byte(requestedPolicy), &requested); err != nil {
		t.Fatalf("decode requested topology: %v", err)
	}
	setTopoCalled := false
	steerCalled := false
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		CommandRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != easyMeshCommandPath {
				t.Fatalf("command=%q", name)
			}
			if slices.Equal(args, []string{"td", "s2"}) {
				return []byte(strings.ReplaceAll(easyMeshNativeSteerFixture, "0x40, Role: |BH|", "0x00, Role:")), nil
			}
			steerCalled = true
			return nil, nil
		},
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
			case "getRealTopo":
				return []byte(starTopology), nil
			case "setTopo":
				setTopoCalled = true
				return []byte(`{}`), nil
			default:
				return nil, wusp.ErrUSPPathUnsupported
			}
		},
	})
	err := backend.applyAndVerifyEasyMeshTopology(
		t.Context(),
		requestedPolicy,
		requested,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "not advertising an operational backhaul BSS") {
		t.Fatalf("applyAndVerifyEasyMeshTopology error=%v", err)
	}
	if setTopoCalled || steerCalled {
		t.Fatalf("unsafe mutation reached device: setTopo=%t steer=%t", setTopoCalled, steerCalled)
	}
}

func TestEasyMeshLiveTopologyChangeIsPushedThroughObserver(t *testing.T) {
	const starTopology = `{"topo":[{"mac":"00:03:7F:BA:DB:AD","pMac":"","hops":0,"name":"Controller"},{"mac":"E0:5D:54:4B:E5:DC","pMac":"00:03:7F:BA:DB:AD","hops":1,"name":"Relay A"},{"mac":"E0:5D:54:4B:E6:CF","pMac":"00:03:7F:BA:DB:AD","hops":1,"name":"Relay B"}]}`
	const chainTopology = `{"topo":[{"mac":"00:03:7F:BA:DB:AD","pMac":"","hops":0,"name":"Controller"},{"mac":"E0:5D:54:4B:E5:DC","pMac":"00:03:7F:BA:DB:AD","hops":1,"name":"Relay A"},{"mac":"E0:5D:54:4B:E6:CF","pMac":"E0:5D:54:4B:E5:DC","hops":2,"name":"Relay B"}]}`

	star, ok := parseOpenWrtRealTopo([]byte(starTopology))
	if !ok {
		t.Fatal("parse star topology")
	}
	chain, ok := parseOpenWrtRealTopo([]byte(chainTopology))
	if !ok {
		t.Fatal("parse chain topology")
	}
	if easyMeshLiveFingerprint(star.root) == easyMeshLiveFingerprint(chain.root) {
		t.Fatal("parent graph change did not change live fingerprint")
	}

	updates := make(chan *wusp.Message, 1)
	backend := NewOpenWrtBackend(OpenWrtBackendOptions{
		EasyMeshObserver: func(msg *wusp.Message) { updates <- msg },
	})
	defer backend.Close()
	backend.notifyEasyMeshLiveTopology(chain.root)
	update := <-updates

	values := make(map[string]string, len(update.Fields))
	for _, field := range update.Fields {
		values[field.Path] = wusp.ValueToString(field.Val)
	}
	foundRelayParent := false
	for path, value := range values {
		if !strings.HasPrefix(path, "Device.WUSP_MeshTelemetry.Node.") ||
			!strings.HasSuffix(path, ".MACAddress") ||
			!strings.EqualFold(value, "E0:5D:54:4B:E6:CF") {
			continue
		}
		prefix := strings.TrimSuffix(path, "MACAddress")
		foundRelayParent = strings.EqualFold(values[prefix+"ParentMACAddress"], "E0:5D:54:4B:E5:DC")
		if foundRelayParent {
			break
		}
	}
	if !foundRelayParent {
		t.Fatal("live topology push did not include Relay B's new parent")
	}
}
