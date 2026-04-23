//go:build linux && !qmi && !mbim

// Pure-Go Linux modem controller using AT commands + sysfs.
// For CGo-accelerated access, build with: -tags qmi (libqmi) or -tags mbim (libmbim)

package modem

func newController() Controller { return &atController{} }
