package fiberonu

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"wantastic-agent/internal/wusp"
)

// SetONUParam applies a Device.WUSP_ONU.* write from the console onto the
// vendor device, and the TR-181 Device.WiFi.* names of the Wi-Fi settings.
// enableWrite persists the Enable flag through the caller; it is called for
// the Enable leaf only.
func SetONUParam(opts Options, path string, value wusp.Value, enableWrite func(bool) error) error {
	path = strings.TrimSpace(path)
	switch path {
	case wusp.WUSPONUPrefix + "Enable":
		if enableWrite == nil {
			return wusp.ErrUSPPathUnsupported
		}
		return enableWrite(value.AsBool())
	}
	if strings.HasPrefix(path, wusp.WUSPONUPrefix+"Network.") {
		return SetONUNetworkParam(context.Background(), opts, path, value)
	}
	if strings.HasPrefix(path, wifiPrefix) {
		// TR-181 names of the Wi-Fi settings (control_wifi_tr181.go).
		return SetWiFiTR181Param(context.Background(), opts, path, value)
	}
	return wusp.ErrUSPPathUnsupported
}

// ONUOperate runs Device.WUSP_ONU Operate commands on behalf of the agent.
// Commands execute only when the console asks, never on a timer.
func ONUOperate(ctx context.Context, opts Options, cmd string, input *wusp.Message) error {
	switch strings.TrimSpace(cmd) {
	case wusp.WUSPONURebootCommand:
		// The vendor's own restart path: mag-reset.asp with rebootflag
		// (TCWebApi_set("System_Entry","reboot_type","restoreFlag")).
		if err := postCGIForm(ctx, opts, "mag-reset.asp", url.Values{
			"rebootflag":  {"1"},
			"restoreFlag": {"1"},
		}); err == nil {
			return nil
		}
		// Fallback: the device's own reboot binary (busybox), which the
		// agent runs as root on-device.
		return exec.CommandContext(ctx, "reboot").Run()
	case wusp.WUSPONUFactoryRestoreCommand:
		// Factory restore + restart: defaultflag=1, restoreflag2=7
		// (mag-reset.asp ReFactoryboot; 5 for the ZHJ province build).
		return postCGIForm(ctx, opts, "mag-reset.asp", url.Values{
			"defaultflag":  {"1"},
			"restoreflag2": {"7"},
		})
	case wusp.WUSPONUBackupConfigCommand:
		text, err := OperateBackupConfig(ctx, opts)
		if err != nil {
			return err
		}
		if input != nil {
			input.Set(wusp.WUSPONUPrefix+"Config", wusp.String(text))
		}
		return nil
	case wusp.WUSPONURestoreConfigCommand:
		return OperateRestoreConfig(ctx, opts, input)
	case wusp.WUSPONUUpgradeCommand:
		return OperateUpgrade(ctx, opts, input)
	default:
		if strings.HasPrefix(cmd, wusp.WUSPONUPrefix+"Network.") {
			return ONUNetworkOperate(ctx, opts, cmd, input)
		}
		return wusp.ErrUSPPathUnsupported
	}
}

// postCGIForm POSTs a form to the loopback boa API (no authentication is
// needed from localhost, matching the vendor UI's own forms).
func postCGIForm(ctx context.Context, opts Options, cgi string, form url.Values) error {
	client := &http.Client{Timeout: 10 * time.Second}
	target := strings.TrimSuffix(opts.cgiBase(), "/") + "/cgi-bin/" + cgi
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return nil
}

// OperateBackupConfig dumps the vendor configuration with
// backuprestorecmd -b and returns its text.
func OperateBackupConfig(ctx context.Context, opts Options) (string, error) {
	target := filepath.Join(os.TempDir(), fmt.Sprintf("onu-config-%d.cfg", time.Now().UnixNano()))
	// backuprestorecmd -b <source> <target>; the source is the vendor
	// romfile partition (mtd1).
	out, err := exec.CommandContext(ctx, "backuprestorecmd", "-b", "/dev/mtd1", target).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("onu: backup config: %v: %s", err, strings.TrimSpace(string(out)))
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return "", fmt.Errorf("onu: read backup: %w", err)
	}
	os.Remove(target)
	return string(data), nil
}

// OperateRestoreConfig applies a configuration text carried in the Operate
// input field "Config".
func OperateRestoreConfig(ctx context.Context, opts Options, input *wusp.Message) error {
	text := OperateInputString(input, "Config")
	if text == "" {
		return fmt.Errorf("onu: RestoreConfig() requires a Config input field")
	}
	target := filepath.Join(os.TempDir(), fmt.Sprintf("onu-restore-%d.cfg", time.Now().UnixNano()))
	if err := os.WriteFile(target, []byte(text), 0600); err != nil {
		return fmt.Errorf("onu: stage restore config: %w", err)
	}
	defer os.Remove(target)
	out, err := exec.CommandContext(ctx, "backuprestorecmd", "-r", target, "/dev/mtd1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("onu: restore config: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// OperateUpgrade applies a firmware image staged by the agent's upload
// handler through the vendor upgrade cgi.
func OperateUpgrade(ctx context.Context, opts Options, input *wusp.Message) error {
	name := OperateInputString(input, "FileName")
	if name == "" {
		return fmt.Errorf("onu: Upgrade() requires a FileName input (the staged image file)")
	}
	data, err := os.ReadFile(filepath.Join(OperateStagingDir, filepath.Base(name)))
	if err != nil {
		return fmt.Errorf("onu: read staged image: %w", err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filepath.Base(name))
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	writer.Close()

	client := &http.Client{Timeout: 15 * time.Minute}
	target := strings.TrimSuffix(opts.cgiBase(), "/") + "/cgi-bin/upgrade.asp"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("onu: upgrade: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return nil
}

// OperateInputString reads a string input field from an Operate input
// message by its leaf name, e.g. "FileName" or "Config".
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

// OperateStagingDir is where the agent stages uploaded files for Operate
// commands; overridden by the agent runtime to its transfer directory.
var OperateStagingDir = os.TempDir()
