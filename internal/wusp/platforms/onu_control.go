package platforms

import (
	"context"

	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/fiberonu"
)

// collectONUStatic fills Device.WUSP_ONU.* through the shared fiberonu
// collector. Every source failure degrades to Status/StatusDetail; it
// never fails the whole collect.
func (b *hostBackend) collectONUStatic(ctx context.Context, msg *wusp.Message) {
	fiberonu.CollectONU(ctx, fiberonu.Options{}, b.onuEnabled(), msg)
}

// onuEnabled reports whether ONU collection/control is on. Defaults to
// enabled once the ONU platform is detected.
func (b *hostBackend) onuEnabled() bool {
	state, err := b.readState()
	if err != nil {
		return true
	}
	return state.ONUEnabled == nil || *state.ONUEnabled
}

// setONUParam applies a Device.WUSP_ONU.* write from the console onto the
// vendor device through the shared fiberonu control surface. Unsupported
// leaves return wusp.ErrUSPPathUnsupported.
func (b *hostBackend) setONUParam(ctx context.Context, path string, value wusp.Value) error {
	return fiberonu.SetONUParam(fiberonu.Options{}, path, value, func(enabled bool) error {
		return b.updateState(func(state *hostState) {
			state.ONUEnabled = &enabled
		})
	})
}

// ONUOperate runs Device.WUSP_ONU Operate commands on behalf of the agent.
// Commands execute only when the console asks, never on a timer.
func (b *hostBackend) ONUOperate(ctx context.Context, cmd string, input *wusp.Message) error {
	if b.kind != KindONU {
		return wusp.ErrUSPPathUnsupported
	}
	return fiberonu.ONUOperate(ctx, fiberonu.Options{}, cmd, input)
}

// ONUOperateWithDir runs Upgrade-style commands that read staged files
// from the agent's transfer directory.
func (b *hostBackend) ONUOperateWithDir(ctx context.Context, cmd, stagingDir string, input *wusp.Message) error {
	if b.kind != KindONU {
		return wusp.ErrUSPPathUnsupported
	}
	previous := fiberonu.OperateStagingDir
	fiberonu.OperateStagingDir = stagingDir
	defer func() { fiberonu.OperateStagingDir = previous }()
	return fiberonu.ONUOperate(ctx, fiberonu.Options{}, cmd, input)
}
