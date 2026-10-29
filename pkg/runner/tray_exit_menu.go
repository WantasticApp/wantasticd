package runner

import (
	"fmt"
	"strings"

	"wantastic-agent/internal/agent"
	"wantastic-agent/internal/device"
)

// maxExitMenuItems bounds the "Use exit node" submenu.
const maxExitMenuItems = 20

type exitMenuItem struct {
	IP      string
	Title   string
	Tooltip string
	Checked bool
	Enabled bool
}

// exitMenuState is everything the tray shows for exit-node mode; derived
// from daemon status by a pure function so it is unit tested.
type exitMenuState struct {
	Header       string
	OfferTitle   string
	OfferTooltip string
	OfferChecked bool
	OfferEnabled bool
	UseEnabled   bool
	UseTooltip   string
	NoneChecked  bool
	NoneEnabled  bool
	Items        []exitMenuItem
}

func deriveExitMenu(st *agent.StatusResponse) exitMenuState {
	m := exitMenuState{
		Header:       "Exit node: unavailable",
		OfferTitle:   "Allow this device as exit node",
		OfferTooltip: "Let other devices in this network send their internet traffic through this one",
		NoneChecked:  true,
	}
	if st == nil || !st.Running {
		m.OfferTooltip = "Daemon not running"
		m.UseTooltip = "Daemon not running"
		return m
	}
	es := st.ExitNodeState
	if es == nil {
		m.OfferTooltip = "The running daemon is older and has no exit-node support; restart it"
		m.UseTooltip = m.OfferTooltip
		return m
	}

	m.OfferChecked = es.Offering
	switch {
	case !es.Supported:
		m.OfferTooltip = "Unsupported here: " + es.UnsupportedReason
	case es.OfferError != "":
		m.OfferEnabled = true
		m.OfferTooltip = "Last attempt failed: " + es.OfferError
	default:
		m.OfferEnabled = true
		if es.Offering && len(es.Users) > 0 {
			m.OfferTooltip = fmt.Sprintf("In use by %d peer(s)", len(es.Users))
		}
	}

	m.UseEnabled = es.ClientSupported
	m.NoneEnabled = es.ClientSupported
	if !es.ClientSupported {
		m.UseTooltip = "Using an exit node is not supported on this platform"
	}
	using := ""
	if u := es.Using; u != nil {
		using = u.IP
		m.NoneChecked = false
		name := u.IP
		if u.Hostname != "" {
			name = u.Hostname
		}
		if u.State == "active" {
			m.Header = fmt.Sprintf("Exit node: via %s (%s)", name, u.Path)
		} else {
			m.Header = fmt.Sprintf("Exit node: %s (%s)", name, u.State)
		}
	} else if es.Offering {
		m.Header = "Exit node: sharing this device"
	} else {
		m.Header = "Exit node: off"
	}

	for _, c := range es.Candidates {
		if len(m.Items) == maxExitMenuItems {
			break
		}
		m.Items = append(m.Items, exitCandidateItem(c, using))
	}
	if len(m.Items) == 0 && m.UseTooltip == "" {
		m.UseTooltip = "No other devices online in this network"
	}
	return m
}

func exitCandidateItem(c device.ExitCandidate, using string) exitMenuItem {
	label := c.IP
	if h := strings.TrimSpace(c.Hostname); h != "" {
		label = fmt.Sprintf("%s (%s)", h, c.IP)
	}
	var tags []string
	if !c.Online {
		tags = append(tags, "offline")
	} else {
		tags = append(tags, c.Path)
	}
	switch c.Offers {
	case "yes":
		tags = append(tags, "offers exit")
	case "no":
		tags = append(tags, "not an exit")
	}
	it := exitMenuItem{
		IP:      c.IP,
		Title:   label + " · " + strings.Join(tags, ", "),
		Checked: c.IP == using,
		Enabled: c.Online && c.Offers != "no",
	}
	switch {
	case !c.Online:
		it.Tooltip = "Device is offline"
	case c.Offers == "no":
		it.Tooltip = "That device has not enabled exit-node (Allow this device as exit node)"
	case c.Path != "direct":
		it.Tooltip = "Relayed right now: exit traffic starts once a direct path is up"
	default:
		it.Tooltip = "Send all internet traffic through " + label
	}
	if it.Checked {
		it.Enabled = true // always allow re-selecting the active one
	}
	return it
}
