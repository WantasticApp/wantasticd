package platforms

import (
	"path/filepath"
	"testing"
)

func TestDetectKindOLTReleaseFile(t *testing.T) {
	root := t.TempDir()
	oltRelease := filepath.Join(root, "olt-release")
	mustWriteFile(t, oltRelease, "MODEL=GP8X2G6\nVENDOR=photon\nVERSION=1.1.3.18\n")

	kind := DetectKind(Options{
		OLTReleasePath:  oltRelease,
		SysinfoPath:     filepath.Join(root, "missing-sysinfo"),
		DeviceModelPath: filepath.Join(root, "missing-model"),
	})
	if kind != KindOLT {
		t.Fatalf("DetectKind()=%s want %s", kind, KindOLT)
	}
}

func TestDetectKindOLTSysinfo(t *testing.T) {
	root := t.TempDir()
	sysinfo := filepath.Join(root, "sysinfo.txt")
	mustWriteFile(t, sysinfo, "Sn: 123456790\nKind: OLT\nType: GPON\nSoftwareVersion: 1.1.3.18(release-000513)\nHardwareVersion: 3.0\nModelName: GP8X2G6\nMAC: 00:90:4c:06:a4:27\nVendor: photon\nMgtIP: 192.168.100.100\n")

	kind := DetectKind(Options{
		OLTReleasePath:  filepath.Join(root, "missing-olt-release"),
		SysinfoPath:     sysinfo,
		DeviceModelPath: filepath.Join(root, "missing-model"),
	})
	if kind != KindOLT {
		t.Fatalf("DetectKind()=%s want %s", kind, KindOLT)
	}
}

// An OLT hostname/model must win over the ONU marker rules, since strings
// like "GPON-OLT" contain "pon".
func TestDetectKindOLTBeforeONU(t *testing.T) {
	root := t.TempDir()
	model := filepath.Join(root, "model")
	mustWriteFile(t, model, "GPON-OLT")

	kind := DetectKind(Options{
		OLTReleasePath:  filepath.Join(root, "missing-olt-release"),
		SysinfoPath:     filepath.Join(root, "missing-sysinfo"),
		DeviceModelPath: model,
	})
	if kind != KindOLT {
		t.Fatalf("DetectKind()=%s want %s", kind, KindOLT)
	}
}

func TestDetectKindONUStillWinsForONUModels(t *testing.T) {
	root := t.TempDir()
	model := filepath.Join(root, "model")
	mustWriteFile(t, model, "HSGQ 4-port XPON ONU")

	kind := DetectKind(Options{
		OLTReleasePath:  filepath.Join(root, "missing-olt-release"),
		SysinfoPath:     filepath.Join(root, "missing-sysinfo"),
		DeviceModelPath: model,
	})
	if kind != KindONU {
		t.Fatalf("DetectKind()=%s want %s", kind, KindONU)
	}
}

func TestOLTStatePathAndProductClass(t *testing.T) {
	root := t.TempDir()
	if got := defaultStatePath(KindOLT); got != defaultWantasticStatePath("usp-olt.json") {
		t.Fatalf("defaultStatePath(KindOLT)=%q", got)
	}
	backend := newHostBackend(KindOLT, Options{
		StatePath: filepath.Join(root, "state.json"),
	})
	_ = backend
	if got := defaultHostnamePath(KindOLT); got != "/proc/sys/kernel/hostname" {
		t.Fatalf("defaultHostnamePath(KindOLT)=%q", got)
	}
}

// A proxy deployment forces KindOLT with a remote API URL: the agent runs
// on a mesh device and manages the OLT over its goform API.
func TestOLTProxyModeOptions(t *testing.T) {
	root := t.TempDir()
	backend := newHostBackend(KindOLT, Options{
		StatePath:      filepath.Join(root, "state.json"),
		OLTAPIURL:      "http://192.168.100.100",
		OLTAPIUser:     "admin",
		OLTAPIPassword: "secret",
	})
	client := backend.oltClient()
	if client == nil {
		t.Fatal("oltClient() returned nil")
	}
	if client.BaseURL() != "http://192.168.100.100" {
		t.Fatalf("proxy base URL not applied")
	}
	if backend.oltAPIURL != "http://192.168.100.100" || backend.oltAPIPassword != "secret" {
		t.Fatalf("proxy credentials not stored")
	}
}
