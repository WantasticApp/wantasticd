//go:build !linux

// Non-Linux platforms: cellular modems not supported.

package modem

import "fmt"

type stubController struct{}

func newController() Controller { return &stubController{} }

func (c *stubController) Discover() ([]string, error)             { return nil, nil }
func (c *stubController) GetInfo(string) (*Info, error)            { return nil, fmt.Errorf("modem: not supported on this platform") }
func (c *stubController) GetSignal(string) (*SignalQuality, error) { return nil, fmt.Errorf("modem: not supported on this platform") }
func (c *stubController) Connect(string, string) error             { return fmt.Errorf("modem: not supported on this platform") }
func (c *stubController) Disconnect(string) error                  { return fmt.Errorf("modem: not supported on this platform") }
func (c *stubController) Close() error                             { return nil }
