//go:build tools

package mobile

// gomobile bind needs its runtime package in this module.
import _ "golang.org/x/mobile/bind"
