package fiberolt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// SetOLTParam applies a Device.WUSP_OLT.* write from the console onto the
// vendor device through the binding tables (engine.go). enableWrite
// persists the Enable flag through the caller; it is called for the Enable
// leaf only. Unsupported leaves return wusp.ErrUSPPathUnsupported.
func SetOLTParam(ctx context.Context, api *Client, path string, value wusp.Value, enableWrite func(bool) error) error {
	return Set(ctx, &Env{API: api, EnableWrite: enableWrite}, path, value)
}

// SetOLTParamWithCLI is SetOLTParam with the FOS command line available
// to bindings that need it.
func SetOLTParamWithCLI(ctx context.Context, api *Client, cli *CLI, path string, value wusp.Value, enableWrite func(bool) error) error {
	env := envFor(api, cli)
	env.EnableWrite = enableWrite
	return Set(ctx, env, path, value)
}

// ONURowByIndex resolves a position in the raw web ONU list to a vendor
// ONU ID (like "0/1/1"). Empty when the row is unknown.
//
// Deprecated: the WUSP ONU table is sorted and merged with CLI-only rows,
// so its instance numbers do not follow the raw web order; Set resolves
// ONU.{i} through the collected snapshot instead.
func ONURowByIndex(ctx context.Context, api *Client, index uint64) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := api.EnsureLogin(ctx); err != nil {
		return ""
	}
	ont, err := api.OntListBrife(ctx)
	if err != nil {
		return ""
	}
	position := 1
	for _, row := range ont.List {
		id := RowString(row, "onuid", "id", "index")
		if uint64(position) == index {
			return id
		}
		position++
	}
	return ""
}

// OLTOperate runs Device.WUSP_OLT Operate commands on behalf of the agent.
// Commands execute only when the console asks, never on a timer. Output
// fields (e.g. BackupConfig's Config) are written into input when it is
// non-nil, which is how callers have always read them.
func OLTOperate(ctx context.Context, api *Client, cmd string, input *wusp.Message) error {
	out, err := Operate(ctx, &Env{API: api}, cmd, input)
	if err != nil {
		return err
	}
	if input != nil && out != nil {
		for _, f := range out.Fields {
			input.Set(f.Path, f.Val)
		}
	}
	return nil
}

// OperateInputString reads a string input field from an Operate input
// message by its leaf name, e.g. "Index" under the command object.
func OperateInputString(input *wusp.Message, leaf string) string {
	if input == nil {
		return ""
	}
	for _, field := range input.Fields {
		if strings.HasSuffix(field.Path, leaf) || strings.HasSuffix(field.Path, leaf+".") {
			return wusp.ValueToString(field.Val)
		}
	}
	return ""
}

// parseIndexedPath splits "Prefix.N.Leaf" into the 1-based row index and the
// leaf name. Mirrors the platforms helper so fiberolt stays stdlib-only.
func parseIndexedPath(path, prefix string) (uint64, string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(path), prefix)
	if !ok {
		return 0, "", false
	}
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	index, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || index == 0 {
		return 0, "", false
	}
	leaf := strings.TrimSpace(parts[1])
	if leaf == "" || strings.Contains(leaf, ".") {
		return 0, "", false
	}
	return index, leaf, true
}

// OperateUpgrade applies a firmware image staged by the agent's upload
// handler. The Operate input must carry the staged file name (field
// FileName); stagingDir is the agent's transfer directory.
func OperateUpgrade(ctx context.Context, api *Client, input *wusp.Message) error {
	return operateUpgrade(ctx, api, OperateStagingDir, input)
}

func operateUpgrade(ctx context.Context, api *Client, stagingDir string, input *wusp.Message) error {
	name := OperateInputString(input, "FileName")
	if name == "" {
		return fmt.Errorf("olt: Upgrade() requires a FileName input (the staged image file)")
	}
	data, err := os.ReadFile(filepath.Join(stagingDir, filepath.Base(name)))
	if err != nil {
		return fmt.Errorf("olt: read staged image: %w", err)
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	if err := api.UpgradeImage(ctx, filepath.Base(name), data); err != nil {
		return fmt.Errorf("olt: upgrade: %w", err)
	}
	return nil
}

// OperateBackupConfig returns the running configuration text; the caller
// embeds it into the Operate result message (field Config).
func OperateBackupConfig(ctx context.Context, api *Client) (string, error) {
	if err := api.EnsureLogin(ctx); err != nil {
		return "", fmt.Errorf("olt: login: %w", err)
	}
	text, err := api.DownloadConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("olt: backup config: %w", err)
	}
	return text, nil
}

// OperateRestoreConfig applies a configuration text carried in the Operate
// input field "Config".
func OperateRestoreConfig(ctx context.Context, api *Client, input *wusp.Message) error {
	text := OperateInputString(input, "Config")
	if text == "" {
		return fmt.Errorf("olt: RestoreConfig() requires a Config input field")
	}
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	if err := api.RestoreConfig(ctx, "olt_config.txt", text); err != nil {
		return fmt.Errorf("olt: restore config: %w", err)
	}
	return nil
}

// OperateStagingDir is where the agent stages uploaded files for Operate
// commands; overridden by the agent runtime to its transfer directory.
var OperateStagingDir = os.TempDir()

// AddProvisionedONU provisions one ONU in the authentication table.
func AddProvisionedONU(ctx context.Context, api *Client, onuID, mode, info, lineID, desc string) error {
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.ProvisionONU(ctx, ProvisionedONU{OnuID: onuID, Mode: mode, Info: info, LineID: lineID, Desc: desc})
}

// DeleteProvisionedONU removes one ONU from the authentication table.
func DeleteProvisionedONU(ctx context.Context, api *Client, onuID string) error {
	if err := api.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("olt: login: %w", err)
	}
	return api.DeleteProvisionedONU(ctx, onuID)
}

// ProvisionedONUByIndex resolves a WUSP ProvisionedONU table row (1-based)
// back to the ONU ID (like "0/1/1"), or "" when unknown.
func ProvisionedONUByIndex(ctx context.Context, api *Client, index uint64) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := api.EnsureLogin(ctx); err != nil {
		return ""
	}
	rows, err := api.OntAuthList(ctx)
	if err != nil || index == 0 || int(index) > len(rows) {
		return ""
	}
	return rows[index-1].OnuID
}
