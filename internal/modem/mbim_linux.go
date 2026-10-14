//go:build linux && mbim && !qmi

// CGo libmbim implementation for MBIM modems (Sierra Wireless, Intel XMM, etc.)
// Build: CGO_ENABLED=1 go build -tags mbim
// Requires: libmbim-glib-dev (or libmbim on OpenWrt)

package modem

/*
#cgo LDFLAGS: -lmbim-glib -lglib-2.0 -lgio-2.0 -lgobject-2.0
#cgo CFLAGS: -I/usr/include/libmbim-glib -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/lib/x86_64-linux-gnu/glib-2.0/include

#include <libmbim-glib/libmbim-glib.h>
#include <stdlib.h>
#include <string.h>

struct mbim_modem_info {
    char model[128];
    char manufacturer[128];
    char revision[128];
    char imei[32];
    char imsi[32];
    char iccid[32];
    int  rssi;
    int  rsrp;
    int  error_rate;
    int  tech;       // MbimDataClass bitmask → simplified
    int  reg_state;  // 0=not, 1=home, 2=searching, 3=denied, 5=roaming
    char provider[64];
    uint32_t cell_id;
    uint32_t tac;
    int  connected;
    char ip[64];
};

static int c_mbim_get_info(const char *device_path, struct mbim_modem_info *out) {
    memset(out, 0, sizeof(*out));

    GError *error = NULL;
    GFile *file = g_file_new_for_path(device_path);
    MbimDevice *device = mbim_device_new_finish(
        mbim_device_new(file, NULL, NULL, NULL), &error);
    g_object_unref(file);
    if (!device) {
        if (error) g_error_free(error);
        return -1;
    }

    if (!mbim_device_open_full_sync(device,
            MBIM_DEVICE_OPEN_FLAGS_PROXY, 30, NULL, &error)) {
        g_object_unref(device);
        if (error) g_error_free(error);
        return -2;
    }

    // Query device caps (model, manufacturer, IMEI)
    MbimMessage *req = mbim_message_device_caps_query_new(NULL);
    MbimMessage *resp = mbim_device_command_sync(device, req, 10, NULL, &error);
    mbim_message_unref(req);

    if (resp) {
        MbimDeviceType dev_type;
        const char *manufacturer = NULL, *model = NULL, *revision = NULL;
        const char *imei = NULL;
        MbimCellularClass cell_class;
        MbimDataClass data_class;
        uint32_t max_sessions;

        if (mbim_message_device_caps_response_parse(resp,
                &dev_type, &cell_class, NULL, NULL, NULL,
                &data_class, NULL, &max_sessions,
                &manufacturer, &model, &revision, &imei, NULL)) {
            if (manufacturer) strncpy(out->manufacturer, manufacturer, sizeof(out->manufacturer)-1);
            if (model) strncpy(out->model, model, sizeof(out->model)-1);
            if (revision) strncpy(out->revision, revision, sizeof(out->revision)-1);
            if (imei) strncpy(out->imei, imei, sizeof(out->imei)-1);
        }
        mbim_message_unref(resp);
    }

    // Query subscriber (IMSI, ICCID)
    req = mbim_message_subscriber_ready_status_query_new(NULL);
    resp = mbim_device_command_sync(device, req, 10, NULL, &error);
    mbim_message_unref(req);
    if (resp) {
        MbimSubscriberReadyState ready;
        const char *subscriber_id = NULL, *sim_iccid = NULL;
        if (mbim_message_subscriber_ready_status_response_parse(resp,
                &ready, &subscriber_id, &sim_iccid,
                NULL, NULL, NULL, NULL, NULL)) {
            if (subscriber_id) strncpy(out->imsi, subscriber_id, sizeof(out->imsi)-1);
            if (sim_iccid) strncpy(out->iccid, sim_iccid, sizeof(out->iccid)-1);
        }
        mbim_message_unref(resp);
    }

    // Query registration (operator, tech, cell)
    req = mbim_message_register_state_query_new(NULL);
    resp = mbim_device_command_sync(device, req, 10, NULL, &error);
    mbim_message_unref(req);
    if (resp) {
        MbimNwError nw_error;
        MbimRegisterState reg;
        MbimRegisterMode mode;
        MbimDataClass avail_data;
        MbimDataClass current_data;
        const char *provider_id = NULL, *provider_name = NULL;
        const char *roaming = NULL;
        MbimRegistrationFlag flags;

        if (mbim_message_register_state_response_parse(resp,
                &nw_error, &reg, &mode,
                &avail_data, &current_data,
                &provider_id, &provider_name,
                &roaming, &flags, NULL)) {
            if (provider_name) strncpy(out->provider, provider_name, sizeof(out->provider)-1);
            switch (reg) {
                case MBIM_REGISTER_STATE_HOME:       out->reg_state = 1; break;
                case MBIM_REGISTER_STATE_ROAMING:    out->reg_state = 5; break;
                case MBIM_REGISTER_STATE_SEARCHING:  out->reg_state = 2; break;
                case MBIM_REGISTER_STATE_DENIED:     out->reg_state = 3; break;
                default: break;
            }
            // Derive tech from data class
            if (current_data & MBIM_DATA_CLASS_5G_NR)      out->tech = 4;
            else if (current_data & MBIM_DATA_CLASS_LTE)    out->tech = 3;
            else if (current_data & (MBIM_DATA_CLASS_UMTS | MBIM_DATA_CLASS_HSDPA | MBIM_DATA_CLASS_HSUPA)) out->tech = 2;
            else if (current_data & (MBIM_DATA_CLASS_GPRS | MBIM_DATA_CLASS_EDGE)) out->tech = 1;
        }
        mbim_message_unref(resp);
    }

    // Query signal
    req = mbim_message_signal_state_query_new(NULL);
    resp = mbim_device_command_sync(device, req, 10, NULL, &error);
    mbim_message_unref(req);
    if (resp) {
        uint32_t rssi, error_rate;
        if (mbim_message_signal_state_response_parse(resp,
                &rssi, &error_rate, NULL, NULL, NULL, NULL, NULL)) {
            // MBIM RSSI: 0-31 (like CSQ), 99=unknown
            if (rssi <= 31) {
                out->rssi = -113 + (int)rssi * 2;
            }
            out->error_rate = (int)error_rate;
        }
        mbim_message_unref(resp);
    }

    mbim_device_close_sync(device, 10, NULL, NULL);
    g_object_unref(device);
    return 0;
}
*/
import "C"

import (
	"fmt"
	"strings"
	"time"
	"unsafe"
)

// mbimController uses libmbim-glib for MBIM protocol access.
type mbimController struct {
	at atController // embedded AT fallback
}

func newController() Controller { return &mbimController{} }

func (c *mbimController) Close() error { return nil }

func (c *mbimController) Discover() ([]string, error) {
	return c.at.Discover()
}

func (c *mbimController) GetInfo(devicePath string) (*Info, error) {
	if strings.Contains(devicePath, "cdc-wdm") || strings.Contains(devicePath, "mbim") {
		cPath := C.CString(devicePath)
		defer C.free(unsafe.Pointer(cPath))

		var cInfo C.struct_mbim_modem_info
		if C.c_mbim_get_info(cPath, &cInfo) == 0 {
			info := &Info{
				Model:        C.GoString(&cInfo.model[0]),
				Manufacturer: C.GoString(&cInfo.manufacturer[0]),
				Revision:     C.GoString(&cInfo.revision[0]),
				IMEI:         C.GoString(&cInfo.imei[0]),
				IMSI:         C.GoString(&cInfo.imsi[0]),
				ICCID:        C.GoString(&cInfo.iccid[0]),
				Operator:     C.GoString(&cInfo.provider[0]),
				CellID:       uint32(cInfo.cell_id),
				TAC:          uint32(cInfo.tac),
				Connected:    cInfo.connected != 0,
				IPAddress:    C.GoString(&cInfo.ip[0]),
				Interface:    devicePath,
				Protocol:     "mbim",
				CollectedAt:  time.Now(),
				Signal: SignalQuality{
					RSSI: int(cInfo.rssi),
					RSRP: int(cInfo.rsrp),
				},
			}

			switch cInfo.tech {
			case 1: info.Technology = TechGSM
			case 2: info.Technology = TechUMTS
			case 3: info.Technology = TechLTE
			case 4: info.Technology = TechNR5G
			}

			switch cInfo.reg_state {
			case 1: info.Status = RegHome
			case 2: info.Status = RegSearching
			case 3: info.Status = RegDenied
			case 5: info.Status = RegRoaming
			}

			return info, nil
		}
	}

	return c.at.GetInfo(devicePath)
}

func (c *mbimController) GetSignal(devicePath string) (*SignalQuality, error) {
	info, err := c.GetInfo(devicePath)
	if err != nil {
		return nil, err
	}
	return &info.Signal, nil
}

func (c *mbimController) Connect(devicePath, apn string) error {
	return fmt.Errorf("MBIM connect not yet implemented")
}

func (c *mbimController) Disconnect(devicePath string) error {
	return fmt.Errorf("MBIM disconnect not yet implemented")
}
