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
// vendor device. enableWrite persists the Enable flag through the caller;
// it is called for the Enable leaf only. Unsupported leaves return
// wusp.ErrUSPPathUnsupported.
func SetOLTParam(ctx context.Context, api *Client, path string, value wusp.Value, enableWrite func(bool) error) error {
	path = strings.TrimSpace(path)
	switch path {
	case wusp.WUSPOLTPrefix + "Enable":
		if enableWrite == nil {
			return wusp.ErrUSPPathUnsupported
		}
		return enableWrite(value.AsBool())
	}

	if strings.HasPrefix(path, wusp.WUSPOLTPrefix+"Network.") {
		return SetOLTNetworkParam(ctx, api, path, value)
	}

	if index, leaf, ok := parseIndexedPath(path, wusp.WUSPOLTPrefix+"ONU."); ok {
		row := ONURowByIndex(ctx, api, index)
		if row == "" {
			return wusp.ErrUSPPathNotFound
		}
		switch leaf {
		case "Enable":
			if err := api.EnsureLogin(ctx); err != nil {
				return fmt.Errorf("olt: login: %w", err)
			}
			if value.AsBool() {
				return api.OntAction(ctx, "active", []string{row})
			}
			return api.OntAction(ctx, "deactive", []string{row})
		}
	}

	return wusp.ErrUSPPathUnsupported
}

// ONURowByIndex resolves the wusp ONU table row back to a vendor ONU ID
// (like "0/1/1") by asking the live table. Empty when the row is unknown.
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
// Commands execute only when the console asks, never on a timer.
func OLTOperate(ctx context.Context, api *Client, cmd string, input *wusp.Message) error {
	cmd = strings.TrimSpace(cmd)
	switch cmd {
	case wusp.WUSPOLTRebootCommand:
		if err := api.EnsureLogin(ctx); err != nil {
			return fmt.Errorf("olt: login: %w", err)
		}
		return api.SystemAction(ctx, "reboot")
	case wusp.WUSPOLTUpgradeCommand:
		// The image arrives through the WUSP upload channel and is staged by
		// the agent in its transfer directory; the input names the file.
		return OperateUpgrade(ctx, api, input)
	case wusp.WUSPOLTBackupConfigCommand:
		text, err := OperateBackupConfig(ctx, api)
		if err != nil {
			return err
		}
		if input != nil {
			input.Set(wusp.WUSPOLTPrefix+"Config", wusp.String(text))
		}
		return nil
	case wusp.WUSPOLTRestoreConfigCommand:
		return OperateRestoreConfig(ctx, api, input)
	case wusp.WUSPOLTFactoryRestoreCommand:
		if err := api.EnsureLogin(ctx); err != nil {
			return fmt.Errorf("olt: login: %w", err)
		}
		return api.SystemAction(ctx, "restore")
	case wusp.WUSPOLTONURebootCommand, wusp.WUSPOLTONUResetCommand,
		wusp.WUSPOLTONUEnableCommand, wusp.WUSPOLTONUDisableCommand:
		id := OperateInputString(input, "Index")
		if id == "" {
			return fmt.Errorf("olt: %s requires an Index input (ONU ID like 0/1/1)", cmd)
		}
		if err := api.EnsureLogin(ctx); err != nil {
			return fmt.Errorf("olt: login: %w", err)
		}
		switch cmd {
		case wusp.WUSPOLTONURebootCommand:
			return api.OntAction(ctx, "reboot", []string{id})
		case wusp.WUSPOLTONUResetCommand:
			return api.OntAction(ctx, "reset", []string{id})
		case wusp.WUSPOLTONUEnableCommand:
			return api.OntAction(ctx, "active", []string{id})
		default:
			return api.OntAction(ctx, "deactive", []string{id})
		}
	default:
		if strings.HasPrefix(cmd, wusp.WUSPOLTPrefix+"Network.") {
			return OLTNetworkOperate(ctx, api, cmd, input)
		}
		return wusp.ErrUSPPathUnsupported
	}
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
	name := OperateInputString(input, "FileName")
	if name == "" {
		return fmt.Errorf("olt: Upgrade() requires a FileName input (the staged image file)")
	}
	data, err := os.ReadFile(filepath.Join(OperateStagingDir, filepath.Base(name)))
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
