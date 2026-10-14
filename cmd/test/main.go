// Command test is a live-device diagnostic harness for the WUSP data model.
// It is intentionally separate from wantasticd so modem mutations only happen
// when an operator explicitly selects an action.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"wantastic-agent/internal/modem"
	"wantastic-agent/internal/wusp"
	"wantastic-agent/internal/wusp/platforms"
)

type field struct {
	Path  string `json:"path"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type report struct {
	CollectedAt time.Time                  `json:"collected_at"`
	Devices     []string                   `json:"devices,omitempty"`
	Modems      []*modem.Info              `json:"modems,omitempty"`
	GNSS        map[string]*modem.GNSSInfo `json:"gnss,omitempty"`
	Fields      []field                    `json:"wusp_fields,omitempty"`
	Errors      []string                   `json:"errors,omitempty"`
}

func main() {
	action := flag.String("action", "snapshot", "snapshot, cache, gnss-start, gnss-stop, gnss-get, sms-list, sms-send, sms-delete, connect, or disconnect")
	device := flag.String("device", "", "modem path; defaults to the first discovered modem")
	cachePath := flag.String("cache-path", "/usrdata/wantastic/etc/wusp-datamodel.cache", "persistent WUSP cache path for cache inspection")
	phone := flag.String("phone", "", "destination number for sms-send")
	message := flag.String("message", "", "text for sms-send")
	index := flag.String("index", "", "message index for sms-delete")
	apn := flag.String("apn", "", "APN for connect")
	kind := flag.String("platform", "auto", "auto, openwrt, linux, or android")
	timeout := flag.Duration("timeout", 45*time.Second, "overall diagnostic timeout")
	rawOnly := flag.Bool("raw-only", false, "collect only the selected raw modem endpoint; skip WUSP projection")
	flag.Parse()
	if *action == "cache" {
		inspectCache(*cachePath)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	ctl := modem.New()
	defer ctl.Close()
	devices, err := ctl.Discover()
	if err != nil {
		fatal(err)
	}
	target := strings.TrimSpace(*device)
	if target == "" && len(devices) > 0 {
		target = devices[0]
	}
	// An explicit device also scopes collection. This is important on Qualcomm
	// targets where multiple at_usb endpoints belong to the same physical modem.
	if strings.TrimSpace(*device) != "" {
		devices = []string{target}
	}

	if *action != "snapshot" {
		if target == "" {
			fatal(fmt.Errorf("no modem discovered; pass -device explicitly"))
		}
		if err := runAction(ctl, target, *action, *phone, *message, *index, *apn); err != nil {
			fatal(err)
		}
	}

	out := report{CollectedAt: time.Now().UTC(), Devices: devices, GNSS: map[string]*modem.GNSSInfo{}}
	for _, dev := range devices {
		info, err := ctl.GetInfo(dev)
		if err != nil {
			out.Errors = append(out.Errors, dev+": "+err.Error())
			continue
		}
		out.Modems = append(out.Modems, info)
	}
	if control, ok := ctl.(modem.ControlController); ok {
		for _, dev := range devices {
			if info, err := control.GetGNSS(dev); err == nil {
				out.GNSS[dev] = info
			}
		}
	}

	if !*rawOnly {
		backend := platforms.NewBackend(platforms.Options{Kind: platforms.Kind(strings.ToLower(*kind))})
		if warmer, ok := backend.(interface{ Warmup(context.Context) error }); ok {
			if err := warmer.Warmup(ctx); err != nil {
				out.Errors = append(out.Errors, "WUSP warmup: "+err.Error())
			}
		}
		msg, err := backend.Collect(ctx,
			"Device.Cellular.", "Device.WUSP_CellularTelemetry.",
			"Device.WUSP_CellularControl.", "Device.WUSP_GNSS.",
			"Device.DeviceInfo.Location.", "Device.IP.Interface.", "Device.Firewall.")
		if err != nil {
			out.Errors = append(out.Errors, "WUSP collect: "+err.Error())
		} else {
			out.Fields = messageFields(msg)
			if err := wusp.ValidateMessageFast(msg); err != nil {
				out.Errors = append(out.Errors, "WUSP validation: "+err.Error())
			}
		}
	}
	writeJSON(out)
}

func inspectCache(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal(fmt.Errorf("read WUSP cache: %w", err))
	}
	msg, err := wusp.DecodeMessageLenient(data)
	if err != nil {
		fatal(fmt.Errorf("decode WUSP cache: %w", err))
	}
	writeJSON(struct {
		Path        string    `json:"path"`
		CollectedAt time.Time `json:"collected_at"`
		Fields      []field   `json:"wusp_fields"`
	}{
		Path:        path,
		CollectedAt: time.Now().UTC(),
		Fields:      messageFields(msg),
	})
}

func runAction(ctl modem.Controller, dev, action, phone, message, index, apn string) error {
	control, ok := ctl.(modem.ControlController)
	if !ok && action != "connect" && action != "disconnect" {
		return fmt.Errorf("selected modem backend does not support control operations")
	}
	switch action {
	case "gnss-start":
		return control.SetGNSS(dev, true)
	case "gnss-stop":
		return control.SetGNSS(dev, false)
	case "gnss-get":
		_, err := control.GetGNSS(dev)
		return err
	case "sms-list":
		result, err := control.ListSMS(dev)
		if err == nil {
			fmt.Fprintln(os.Stderr, result)
		}
		return err
	case "sms-send":
		return control.SendSMS(dev, phone, message)
	case "sms-delete":
		return control.DeleteSMS(dev, index)
	case "connect":
		return ctl.Connect(dev, apn)
	case "disconnect":
		return ctl.Disconnect(dev)
	default:
		return fmt.Errorf("unknown action %q", action)
	}
}

func messageFields(msg *wusp.Message) []field {
	if msg == nil {
		return nil
	}
	fields := make([]field, 0, len(msg.Fields))
	for _, f := range msg.Fields {
		fields = append(fields, field{Path: f.Path, Type: fmt.Sprint(f.Val.Tag), Value: wusp.ValueToString(f.Val)})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Path < fields[j].Path })
	return fields
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "test:", err)
	os.Exit(1)
}
