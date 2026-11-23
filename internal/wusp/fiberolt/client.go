package fiberolt

// Package fiberolt implements the Wantastic OLT backend for FOS-based GPON
// OLTs (Photon PTF3708 / GP8X2G6 family). It depends only on the standard
// library plus internal/wusp so it stays buildable under TinyGo for the
// embedded fiber agent.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// oltAPIClient talks to the vendor goform web API of FOS-based GPON OLTs
// (Photon PTF3708 / GP8X2G6 family) over loopback. The OLT web server runs
// on the device itself, so the agent never depends on external reachability.
//
// Only net/http and encoding/json are used so the client stays buildable
// under TinyGo for the embedded fiber agent.
type Client struct {
	baseURL  string
	user     string
	password string
	client   *http.Client
	cookie   string // raw session cookie value ("name=value")
}

// oltPort mirrors the port[] entries of goform/getSysStatus.
type Port struct {
	PortNum   string `json:"portNum"`
	PortName  string `json:"portName"`
	PortDesc  string `json:"portDesc"`
	PortSpeed string `json:"portSpeed"`
	// PortStatus is "1" for up, anything else for down.
	PortStatus string `json:"portStatus"`
	// Online/Offline hold the ONU counts on PON ports ("01"/"00" style).
	Online  string `json:"online"`
	Offline string `json:"offline"`
}

// oltSysStatus mirrors goform/getSysStatus.
type SysStatus struct {
	RunTime       string `json:"runTime"`
	CPUPercent    string `json:"cpuPercent"`
	MemoryPercent string `json:"memoryPercent"`
	Temp1Value    string `json:"temp1value"`
	Temp2Value    string `json:"temp2value"`
	Fan1          string `json:"fan1"`
	Fan2          string `json:"fan2"`
	Fan3          string `json:"fan3"`
	SoftwareVer   string `json:"softwareVersion"`
	HardwareVer   string `json:"hardwareVersion"`
	DeviceName    string `json:"deviceName"`
	MAC           string `json:"mac"`
	SN            string `json:"sn"`
	Ports         []Port `json:"port"`
}

// oltOntEntry mirrors one row of goform/getOntListBrife's list. The vendor
// changes key names between FOS releases, so the client keeps the raw map
// and exposes tolerant getters instead of a fixed struct.
type OntEntry map[string]any

// OntList mirrors goform/getOntListBrife.
type OntList struct {
	List        []OntEntry `json:"list"`
	PONPortList []string   `json:"ponPortList"`
}

func NewClient(baseURL, user, password string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "http://127.0.0.1"
	}
	if user == "" {
		user = "admin"
	}
	if password == "" {
		password = "admin"
	}
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		user:     user,
		password: password,
		client:   &http.Client{Timeout: 8 * time.Second},
	}
}

// BaseURL reports the API base the client talks to.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// post sends a JSON POST to the goform API and decodes the JSON reply.
// The vendor API answers HTTP 200 with a JSON body even on errors, so a
// non-200 status is returned as an error and the body is returned as-is.
func (c *Client) post(ctx context.Context, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if setCookie := resp.Header.Get("Set-Cookie"); setCookie != "" {
		c.cookie = setCookie
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("olt api %s: http %d: %s", path, resp.StatusCode, truncateBody(raw))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("olt api %s: %v", path, err)
	}
	return nil
}

// EnsureLogin authenticates against login/Auth when needed. The vendor web
// UI Base64-encodes the password client-side; the API mirrors that.
func (c *Client) EnsureLogin(ctx context.Context) error {
	var resp struct {
		ErrCode string `json:"errCode"`
	}
	err := c.post(ctx, "/login/Auth", map[string]string{
		"userName": c.user,
		"password": base64.StdEncoding.EncodeToString([]byte(c.password)),
	}, &resp)
	if err != nil {
		return err
	}
	if resp.ErrCode != "success" {
		return fmt.Errorf("olt api login: errCode=%s", resp.ErrCode)
	}
	return nil
}

// SysStatus fetches the device summary and port table.
func (c *Client) SysStatus(ctx context.Context) (*SysStatus, error) {
	var out SysStatus
	if err := c.post(ctx, "/goform/getSysStatus", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// OntListBrife fetches the live ONU table for all PON ports.
func (c *Client) OntListBrife(ctx context.Context) (*OntList, error) {
	var out OntList
	if err := c.post(ctx, "/goform/getOntListBrife", map[string]any{"PonPortName": "all"}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// OntDetail fetches per-ONU detail (optical power, distance, run state).
func (c *Client) OntDetail(ctx context.Context, onuID string) (OntEntry, error) {
	var out struct {
		List []OntEntry `json:"list"`
	}
	if err := c.post(ctx, "/goform/getOntDetail", map[string]any{"onuid": onuID}, &out); err != nil {
		return nil, err
	}
	if len(out.List) == 0 {
		return nil, fmt.Errorf("olt api getOntDetail: no row for %s", onuID)
	}
	return out.List[0], nil
}

// OntAction applies one of the vendor ONU actions (reboot, reset, active,
// deactive) to the given ONU IDs. The goform endpoints take a list of rows
// keyed by onuid.
func (c *Client) OntAction(ctx context.Context, action string, onuIDs []string) error {
	list := make([]map[string]string, 0, len(onuIDs))
	for _, id := range onuIDs {
		list = append(list, map[string]string{"onuid": id})
	}
	endpoint := map[string]string{
		"reboot":   "/goform/setOntListReboot",
		"reset":    "/goform/setOntListReset",
		"active":   "/goform/setOntListActive",
		"deactive": "/goform/setOntListDeactive",
	}[action]
	if endpoint == "" {
		return fmt.Errorf("olt api: unknown ONU action %q", action)
	}
	return c.post(ctx, endpoint, map[string]any{"list": list}, nil)
}

// SystemAction triggers a device-level action (reboot, restore).
func (c *Client) SystemAction(ctx context.Context, action string) error {
	endpoint := map[string]string{
		"reboot":  "/goform/setSystemReboot",
		"restore": "/goform/setSystemRestore",
	}[action]
	if endpoint == "" {
		return fmt.Errorf("olt api: unknown system action %q", action)
	}
	return c.post(ctx, endpoint, map[string]any{}, nil)
}

// ---- tolerant ONU row accessors -----------------------------------------

func RowString(row OntEntry, keys ...string) string {
	for _, key := range keys {
		if v, ok := row[key]; ok && v != nil {
			if s, ok := v.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func RowFloat(row OntEntry, keys ...string) (float64, bool) {
	for _, key := range keys {
		if v, ok := row[key]; ok && v != nil {
			switch n := v.(type) {
			case float64:
				return n, true
			case string:
				if f, err := strconv.ParseFloat(strings.TrimSpace(n), 64); err == nil {
					return f, true
				}
			}
		}
	}
	return 0, false
}

func RowUint(row OntEntry, keys ...string) (uint64, bool) {
	for _, key := range keys {
		if v, ok := row[key]; ok && v != nil {
			switch n := v.(type) {
			case float64:
				return uint64(n), true
			case string:
				if u, err := strconv.ParseUint(strings.TrimSpace(n), 10, 64); err == nil {
					return u, true
				}
			}
		}
	}
	return 0, false
}

func ParsePercent(value string) uint {
	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "%"))
	if n, err := strconv.ParseFloat(value, 64); err == nil && n >= 0 && n <= 100 {
		return uint(n)
	}
	return 0
}

func ParseDecimal(value string) (float64, bool) {
	if n, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
		return n, true
	}
	return 0, false
}

// parseOLTFanRPM extracts the RPM out of vendor fan strings like
// "WORK     RPM: 6600" or "STOP".
func ParseFanRPM(value string) uint {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "STOP") {
		return 0
	}
	idx := strings.LastIndex(value, ":")
	if idx < 0 {
		return 0
	}
	if rpm, err := strconv.ParseUint(strings.TrimSpace(value[idx+1:]), 10, 64); err == nil {
		return uint(rpm)
	}
	return 0
}

func truncateBody(raw []byte) string {
	if len(raw) > 128 {
		return string(raw[:128]) + "..."
	}
	return string(raw)
}

// SystemLogEntry is one row of goform/getSystemLogList.
type SystemLogEntry struct {
	Index   string `json:"index"`
	LogTime string `json:"logTime"`
	LogType string `json:"logType"`
	LogTips string `json:"logTips"`
}

// SystemLog fetches the device log buffer through the web API.
func (c *Client) SystemLog(ctx context.Context) ([]SystemLogEntry, error) {
	var out struct {
		List []SystemLogEntry `json:"list"`
	}
	if err := c.post(ctx, "/goform/getSystemLogList", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.List, nil
}

// LineProfile is one row of goform/getLineprofileList.
type LineProfile struct {
	ProfileID     string `json:"profileid"`
	ProfileName   string `json:"profilename"`
	ONTType       string `json:"onttype"`
	MappingMode   string `json:"mapping_mode"`
	TrafficMode   string `json:"traffic_mode"`
	Bind          string `json:"bind"`
	RefMultProfID string `json:"refMultProfileId"`
}

// LineProfiles fetches the GPON line profile table.
func (c *Client) LineProfiles(ctx context.Context) ([]LineProfile, error) {
	var out struct {
		List []LineProfile `json:"list"`
	}
	if err := c.post(ctx, "/goform/getLineprofileList", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.List, nil
}

// ProvisionedONU is one row of goform/getOntListConfig (the ONU auth table).
type ProvisionedONU struct {
	OnuID  string `json:"onuid"`
	Mode   string `json:"mode"`
	Info   string `json:"info"`
	LineID string `json:"lineid"`
	Desc   string `json:"desc"`
}

// OntAuthList fetches the provisioned ONU authentication table.
func (c *Client) OntAuthList(ctx context.Context) ([]ProvisionedONU, error) {
	var out struct {
		List []ProvisionedONU `json:"list"`
	}
	if err := c.post(ctx, "/goform/getOntListConfig", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.List, nil
}

// ProvisionONU adds or updates one row of the ONU auth table. mode is one of
// "sn"/"password"/"mac" depending on the firmware; info carries the
// serial/password/MAC value, lineid the line profile index.
func (c *Client) ProvisionONU(ctx context.Context, p ProvisionedONU) error {
	return c.post(ctx, "/goform/setOntListConfig", map[string]any{
		"onuid":  p.OnuID,
		"mode":   p.Mode,
		"info":   p.Info,
		"lineid": p.LineID,
		"desc":   p.Desc,
	}, nil)
}

// DeleteProvisionedONU removes one row of the ONU auth table.
func (c *Client) DeleteProvisionedONU(ctx context.Context, onuID string) error {
	return c.post(ctx, "/goform/delOntListConfig", map[string]any{"onuid": onuID}, nil)
}

// DownloadConfig pulls the running configuration text (the same file the
// vendor web UI exports as olt_config.txt).
func (c *Client) DownloadConfig(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/cgi-bin/DownloadCfg/olt_config.txt", nil)
	if err != nil {
		return "", err
	}
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download config: http %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// RestoreConfig uploads a configuration text through the vendor import API
// (multipart field "file", ASCII filename).
func (c *Client) RestoreConfig(ctx context.Context, filename, content string) error {
	return c.uploadFile(ctx, "/cgi-bin/uploadCfg", "file", filename, []byte(content))
}

// UpgradeImage uploads a firmware image through the vendor upgrade API
// (multipart field "file", ASCII filename). The device validates and
// applies the image; a reboot is typically required afterwards.
func (c *Client) UpgradeImage(ctx context.Context, filename string, data []byte) error {
	return c.uploadFile(ctx, "/cgi-bin/upgrade", "file", filename, data)
}

// uploadFile posts a multipart/form-data upload with a single file field.
func (c *Client) uploadFile(ctx context.Context, path, field, filename string, data []byte) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(field, filename)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("olt upload %s: http %d: %s", path, resp.StatusCode, truncateBody(raw))
	}
	return nil
}
