// export_test.go exposes internal test hooks to the auth_test package.
package auth

import "time"

// SetTestPollInterval overrides the per-poll sleep used by RunDeviceFlow.
// Pass 0 to poll without any delay (for tests). Pass -1 to restore the default.
func SetTestPollInterval(d time.Duration) {
	testPollInterval = d
}
