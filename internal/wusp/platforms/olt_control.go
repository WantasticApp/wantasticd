package platforms

import (
	"context"

	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/fiberolt"
)

// setOLTParam applies a Device.WUSP_OLT.* write from the console onto the
// vendor device through the shared fiberolt control surface. Unsupported
// leaves return wusp.ErrUSPPathUnsupported.
func (b *hostBackend) setOLTParam(ctx context.Context, path string, value wusp.Value) error {
	return fiberolt.SetOLTParam(ctx, b.oltClient(), path, value, func(enabled bool) error {
		return b.updateState(func(state *hostState) {
			state.OLTEnabled = &enabled
		})
	})
}

// OLTOperate runs Device.WUSP_OLT Operate commands on behalf of the agent.
// Commands execute only when the console asks, never on a timer.
func (b *hostBackend) OLTOperate(ctx context.Context, cmd string, input *wusp.Message) error {
	if b.kind != KindOLT {
		return wusp.ErrUSPPathUnsupported
	}
	return fiberolt.OLTOperate(ctx, b.oltClient(), cmd, input)
}

// OLTOperateWithDir runs Upgrade-style commands that read staged files from
// the agent's transfer directory.
func (b *hostBackend) OLTOperateWithDir(ctx context.Context, cmd, stagingDir string, input *wusp.Message) error {
	if b.kind != KindOLT {
		return wusp.ErrUSPPathUnsupported
	}
	previous := fiberolt.OperateStagingDir
	fiberolt.OperateStagingDir = stagingDir
	defer func() { fiberolt.OperateStagingDir = previous }()
	return fiberolt.OLTOperate(ctx, b.oltClient(), cmd, input)
}
