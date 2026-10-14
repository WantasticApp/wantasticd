//go:build linux && qmi

// CGo libqmi implementation for Qualcomm QMI modems.
// Build: CGO_ENABLED=1 go build -tags qmi
// Requires: libqmi-glib-dev (or libqmi on OpenWrt)

package modem

/*
#cgo LDFLAGS: -lqmi-glib -lglib-2.0 -lgio-2.0 -lgobject-2.0
#cgo CFLAGS: -I/usr/include/libqmi-glib -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/lib/x86_64-linux-gnu/glib-2.0/include

#include <libqmi-glib/libqmi-glib.h>
#include <stdlib.h>
#include <string.h>

// QMI modem info result
struct qmi_modem_info {
    char model[128];
    char manufacturer[128];
    char revision[128];
    char imei[32];
    char imsi[32];
    char iccid[32];
    int  rssi;
    int  rsrp;
    int  rsrq;
    int  sinr;
    int  tech;      // 0=unknown, 1=gsm, 2=umts, 3=lte, 4=nr5g
    int  reg_state; // 0=not, 1=home, 2=searching, 3=denied, 5=roaming
    char operator[64];
    uint32_t cell_id;
    uint16_t lac;
    uint32_t tac;
    int connected;
    char apn[128];
    char ip[64];
};

// Query modem via QMI — synchronous wrapper around the async libqmi API.
// Returns 0 on success, negative on error.
static int c_qmi_get_info(const char *device_path, struct qmi_modem_info *out) {
    memset(out, 0, sizeof(*out));

    GError *error = NULL;
    GFile *file = g_file_new_for_path(device_path);
    QmiDevice *device = qmi_device_new_finish(
        qmi_device_new(file, NULL, NULL, NULL), &error);
    g_object_unref(file);

    if (!device) {
        if (error) g_error_free(error);
        return -1;
    }

    // Open device
    if (!qmi_device_open_sync(device,
            QMI_DEVICE_OPEN_FLAGS_PROXY | QMI_DEVICE_OPEN_FLAGS_AUTO,
            15, NULL, &error)) {
        g_object_unref(device);
        if (error) g_error_free(error);
        return -2;
    }

    // Allocate DMS client for identity info
    QmiClient *dms_client = NULL;
    qmi_device_allocate_client_sync(device, QMI_SERVICE_DMS, QMI_CID_NONE,
                                     15, NULL, &dms_client, &error);

    if (dms_client) {
        // Get manufacturer
        QmiMessageDmsGetManufacturerOutput *mfr_out = NULL;
        mfr_out = qmi_client_dms_get_manufacturer_sync(QMI_CLIENT_DMS(dms_client),
                                                         NULL, 5, NULL, &error);
        if (mfr_out) {
            const char *mfr = NULL;
            if (qmi_message_dms_get_manufacturer_output_get_manufacturer(mfr_out, &mfr, NULL))
                strncpy(out->manufacturer, mfr, sizeof(out->manufacturer) - 1);
            qmi_message_dms_get_manufacturer_output_unref(mfr_out);
        }

        // Get model
        QmiMessageDmsGetModelOutput *model_out = NULL;
        model_out = qmi_client_dms_get_model_sync(QMI_CLIENT_DMS(dms_client),
                                                    NULL, 5, NULL, &error);
        if (model_out) {
            const char *model = NULL;
            if (qmi_message_dms_get_model_output_get_model(model_out, &model, NULL))
                strncpy(out->model, model, sizeof(out->model) - 1);
            qmi_message_dms_get_model_output_unref(model_out);
        }

        // Get IMEI
        QmiMessageDmsGetIdsOutput *ids_out = NULL;
        ids_out = qmi_client_dms_get_ids_sync(QMI_CLIENT_DMS(dms_client),
                                                NULL, 5, NULL, &error);
        if (ids_out) {
            const char *imei = NULL;
            if (qmi_message_dms_get_ids_output_get_imei(ids_out, &imei, NULL))
                strncpy(out->imei, imei, sizeof(out->imei) - 1);
            qmi_message_dms_get_ids_output_unref(ids_out);
        }

        qmi_device_release_client_sync(device, dms_client, QMI_DEVICE_RELEASE_CLIENT_FLAGS_RELEASE_CID, 5, NULL, NULL);
        g_object_unref(dms_client);
    }

    // Allocate NAS client for signal/registration
    QmiClient *nas_client = NULL;
    qmi_device_allocate_client_sync(device, QMI_SERVICE_NAS, QMI_CID_NONE,
                                     15, NULL, &nas_client, &error);

    if (nas_client) {
        // Signal strength
        QmiMessageNasGetSignalStrengthOutput *sig_out = NULL;
        sig_out = qmi_client_nas_get_signal_strength_sync(QMI_CLIENT_NAS(nas_client),
                                                           NULL, NULL, 5, NULL, &error);
        if (sig_out) {
            int8_t strength = 0;
            QmiNasRadioInterface radio = QMI_NAS_RADIO_INTERFACE_UNKNOWN;
            if (qmi_message_nas_get_signal_strength_output_get_signal_strength(
                    sig_out, &strength, &radio, NULL)) {
                out->rssi = (int)strength;
                switch (radio) {
                    case QMI_NAS_RADIO_INTERFACE_GSM:  out->tech = 1; break;
                    case QMI_NAS_RADIO_INTERFACE_UMTS: out->tech = 2; break;
                    case QMI_NAS_RADIO_INTERFACE_LTE:  out->tech = 3; break;
                    case QMI_NAS_RADIO_INTERFACE_5GNR: out->tech = 4; break;
                    default: break;
                }
            }
            qmi_message_nas_get_signal_strength_output_unref(sig_out);
        }

        // Serving system (operator, registration)
        QmiMessageNasGetServingSystemOutput *srv_out = NULL;
        srv_out = qmi_client_nas_get_serving_system_sync(QMI_CLIENT_NAS(nas_client),
                                                          NULL, 5, NULL, &error);
        if (srv_out) {
            QmiNasRegistrationState reg = QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED;
            QmiNasAttachState cs = QMI_NAS_ATTACH_STATE_UNKNOWN;
            QmiNasAttachState ps = QMI_NAS_ATTACH_STATE_UNKNOWN;
            QmiNasNetworkType net = QMI_NAS_NETWORK_TYPE_UNKNOWN;
            if (qmi_message_nas_get_serving_system_output_get_serving_system(
                    srv_out, &reg, &cs, &ps, NULL, &net, NULL)) {
                switch (reg) {
                    case QMI_NAS_REGISTRATION_STATE_REGISTERED:        out->reg_state = 1; break;
                    case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED:    out->reg_state = 0; break;
                    case QMI_NAS_REGISTRATION_STATE_NOT_REGISTERED_SEARCHING: out->reg_state = 2; break;
                    case QMI_NAS_REGISTRATION_STATE_REGISTRATION_DENIED: out->reg_state = 3; break;
                    default: break;
                }
            }

            // Operator name
            const char *desc = NULL;
            if (qmi_message_nas_get_serving_system_output_get_current_plmn(
                    srv_out, NULL, NULL, &desc, NULL)) {
                if (desc) strncpy(out->operator, desc, sizeof(out->operator) - 1);
            }

            // Cell/LAC/TAC
            uint16_t cell_id_16 = 0;
            uint16_t lac_16 = 0;
            if (qmi_message_nas_get_serving_system_output_get_lac_3gpp(srv_out, &lac_16, NULL))
                out->lac = lac_16;
            if (qmi_message_nas_get_serving_system_output_get_cid_3gpp(srv_out, &cell_id_16, NULL))
                out->cell_id = (uint32_t)cell_id_16;

            qmi_message_nas_get_serving_system_output_unref(srv_out);
        }

        qmi_device_release_client_sync(device, nas_client, QMI_DEVICE_RELEASE_CLIENT_FLAGS_RELEASE_CID, 5, NULL, NULL);
        g_object_unref(nas_client);
    }

    qmi_device_close_sync(device, 5, NULL, NULL);
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

// qmiController uses libqmi-glib for direct QMI protocol access.
type qmiController struct {
	at atController // embedded AT fallback
}

func newController() Controller { return &qmiController{} }

func (c *qmiController) Close() error { return nil }

func (c *qmiController) Discover() ([]string, error) {
	return c.at.Discover()
}

func (c *qmiController) GetInfo(devicePath string) (*Info, error) {
	// Try QMI first (for /dev/cdc-wdm* devices)
	if strings.Contains(devicePath, "cdc-wdm") || strings.Contains(devicePath, "qmi") {
		cPath := C.CString(devicePath)
		defer C.free(unsafe.Pointer(cPath))

		var cInfo C.struct_qmi_modem_info
		if C.c_qmi_get_info(cPath, &cInfo) == 0 {
			info := &Info{
				Model:        C.GoString(&cInfo.model[0]),
				Manufacturer: C.GoString(&cInfo.manufacturer[0]),
				Revision:     C.GoString(&cInfo.revision[0]),
				IMEI:         C.GoString(&cInfo.imei[0]),
				IMSI:         C.GoString(&cInfo.imsi[0]),
				ICCID:        C.GoString(&cInfo.iccid[0]),
				Operator:     C.GoString(&cInfo.operator[0]),
				CellID:       uint32(cInfo.cell_id),
				LAC:          uint16(cInfo.lac),
				TAC:          uint32(cInfo.tac),
				Connected:    cInfo.connected != 0,
				APN:          C.GoString(&cInfo.apn[0]),
				IPAddress:    C.GoString(&cInfo.ip[0]),
				Interface:    devicePath,
				Protocol:     "qmi",
				CollectedAt:  time.Now(),
				Signal: SignalQuality{
					RSSI: int(cInfo.rssi),
					RSRP: int(cInfo.rsrp),
					RSRQ: int(cInfo.rsrq),
					SINR: int(cInfo.sinr),
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

	// Fallback to AT commands
	return c.at.GetInfo(devicePath)
}

func (c *qmiController) GetSignal(devicePath string) (*SignalQuality, error) {
	info, err := c.GetInfo(devicePath)
	if err != nil {
		return nil, err
	}
	return &info.Signal, nil
}

func (c *qmiController) Connect(devicePath, apn string) error {
	return fmt.Errorf("QMI connect not yet implemented")
}

func (c *qmiController) Disconnect(devicePath string) error {
	return fmt.Errorf("QMI disconnect not yet implemented")
}
