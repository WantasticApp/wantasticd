package agent

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/platforms"
)

// handleWantasticMeshOperate runs the WantasticMesh Operate commands. Each
// one is a single explicit request from the console; nothing here is ever
// scheduled.
func (r *uspRuntime) handleWantasticMeshOperate(ctx context.Context, cmd string, input *wusp.Message) (*wusp.Message, error) {
	prefix := wusp.WUSPWantasticMeshPrefix
	switch cmd {
	case wusp.WUSPWantasticMeshRestartCommand:
		backend, ok := r.rawBackend.(interface {
			RestartWantasticMesh(context.Context) error
		})
		if !ok {
			return nil, wusp.ErrUSPPathUnsupported
		}
		if err := backend.RestartWantasticMesh(ctx); err != nil {
			return nil, err
		}
		return wantasticMeshOperationStatus("WantasticMesh restarted"), nil
	case wusp.WUSPWantasticMeshSetChannelCommand, wusp.WUSPWantasticMeshSetTxPowerCommand:
		backend, ok := r.rawBackend.(interface {
			SetWantasticMeshChannel(context.Context, platforms.WantasticMeshRadioChange) (string, string, error)
			SetWantasticMeshTxPower(context.Context, platforms.WantasticMeshRadioChange) (string, string, error)
		})
		if !ok {
			return nil, wusp.ErrUSPPathUnsupported
		}
		change, err := wantasticMeshRadioInput(cmd, input)
		if err != nil {
			return nil, err
		}
		var before, after string
		message := ""
		if cmd == wusp.WUSPWantasticMeshSetChannelCommand {
			before, after, err = backend.SetWantasticMeshChannel(ctx, change)
			message = fmt.Sprintf("Channel on %s: %s -> %s", change.Interface, before, after)
		} else {
			before, after, err = backend.SetWantasticMeshTxPower(ctx, change)
			message = fmt.Sprintf("Transmit power on %s: %s -> %s dBm", change.Interface, before, after)
		}
		if err != nil {
			return nil, err
		}
		output := wantasticMeshOperationStatus(message)
		output.Set(prefix+"Radio.Before", wusp.String(before))
		output.Set(prefix+"Radio.After", wusp.String(after))
		return output, nil
	}
	return nil, wusp.ErrUSPPathUnsupported
}

// wantasticMeshRadioInput reads Radio.SetChannel()/SetTxPower() inputs, sent
// as Device.WUSP_WantasticMesh.Radio.<Name> (bare names are accepted too).
func wantasticMeshRadioInput(cmd string, input *wusp.Message) (platforms.WantasticMeshRadioChange, error) {
	change := platforms.WantasticMeshRadioChange{
		Interface:     cellularInputString(input, "Interface"),
		RevertSeconds: 60,
	}
	if change.Interface == "" {
		return change, fmt.Errorf("WantasticMesh radio Interface is required")
	}
	name := "Channel"
	if cmd == wusp.WUSPWantasticMeshSetTxPowerCommand {
		name = "Power"
	}
	text := cellularInputString(input, name)
	if text == "" {
		return change, fmt.Errorf("WantasticMesh radio %s is required", name)
	}
	value, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return change, fmt.Errorf("WantasticMesh radio %s must be a whole number", name)
	}
	change.Value = value
	if text := cellularInputString(input, "RevertSeconds"); text != "" {
		seconds, err := strconv.ParseUint(text, 10, 16)
		if err != nil {
			return change, fmt.Errorf("WantasticMesh RevertSeconds must be a whole number")
		}
		change.RevertSeconds = seconds
	}
	switch strings.ToLower(cellularInputString(input, "Probe")) {
	case "", "false", "0":
	case "true", "1":
		change.Probe = true
	default:
		return change, fmt.Errorf("WantasticMesh Probe must be true or false")
	}
	return change, nil
}

func wantasticMeshOperationStatus(message string) *wusp.Message {
	prefix := wusp.WUSPWantasticMeshPrefix
	output := wusp.NewMessage()
	output.Set(prefix+"LastOperationStatus", wusp.String("Success"))
	output.Set(prefix+"LastOperationCode", wusp.String(wusp.ControlCodeOperationSuccess))
	output.Set(prefix+"LastOperationMessage", wusp.String(message))
	return output
}
