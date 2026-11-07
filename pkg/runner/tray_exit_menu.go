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
		Header:       T("exit.unavailable"),
		OfferTitle:   T("exit.offer.title"),
		OfferTooltip: T("exit.offer.tooltip"),
		NoneChecked:  true,
	}
	if st != nil && st.Claim != nil {
		m.OfferTooltip = T("exit.login.first")
		m.UseTooltip = T("exit.login.first")
		return m
	}
	if st == nil || !st.Running {
		m.OfferTooltip = T("exit.daemon.down")
		m.UseTooltip = T("exit.daemon.down")
		return m
	}
	es := st.ExitNodeState
	if es == nil {
		m.OfferTooltip = T("exit.daemon.old")
		m.UseTooltip = m.OfferTooltip
		return m
	}

	m.OfferChecked = es.Offering
	switch {
	case !es.Supported:
		m.OfferTooltip = T("exit.unsupported", es.UnsupportedReason)
	case es.OfferError != "":
		m.OfferEnabled = true
		m.OfferTooltip = T("exit.offer.error", es.OfferError)
	default:
		m.OfferEnabled = true
		if es.Offering && len(es.Users) > 0 {
			m.OfferTooltip = T("exit.inuse", len(es.Users))
		}
	}

	m.UseEnabled = es.ClientSupported
	m.NoneEnabled = es.ClientSupported
	if !es.ClientSupported {
		m.UseTooltip = T("exit.use.unsupported")
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
			m.Header = T("exit.via", name, u.Path)
		} else {
			m.Header = T("exit.state", name, u.State)
		}
	} else if es.Offering {
		m.Header = T("exit.sharing")
	} else {
		m.Header = T("exit.off")
	}

	for _, c := range es.Candidates {
		if len(m.Items) == maxExitMenuItems {
			break
		}
		m.Items = append(m.Items, exitCandidateItem(c, using))
	}
	if len(m.Items) == 0 && m.UseTooltip == "" {
		m.UseTooltip = T("exit.nodevices")
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
		tags = append(tags, T("tag.offline"))
	} else {
		tags = append(tags, c.Path)
	}
	switch c.Offers {
	case "yes":
		tags = append(tags, T("tag.offers"))
	case "no":
		tags = append(tags, T("tag.notexit"))
	}
	it := exitMenuItem{
		IP:      c.IP,
		Title:   label + " · " + strings.Join(tags, ", "),
		Checked: c.IP == using,
		Enabled: c.Online && c.Offers != "no",
	}
	switch {
	case !c.Online:
		it.Tooltip = T("exit.cand.offline")
	case c.Offers == "no":
		it.Tooltip = T("exit.cand.notenabled", T("exit.offer.title"))
	case c.Path != "direct":
		it.Tooltip = T("exit.cand.relayed")
	default:
		it.Tooltip = T("exit.cand.use", label)
	}
	if it.Checked {
		it.Enabled = true // always allow re-selecting the active one
	}
	return it
}

// withExitLatency adds each candidate's last ping to its title, so picking
// an exit node shows how far each one is.
func withExitLatency(s exitMenuState, latency map[string]agent.PingResult) exitMenuState {
	if len(latency) == 0 {
		return s
	}
	items := make([]exitMenuItem, len(s.Items))
	for i, it := range s.Items {
		if r, ok := latency[it.IP]; ok && r.Sent > 0 {
			if r.Received > 0 {
				it.Title += " · " + T("latency.ms", r.AvgMs)
			} else {
				it.Title += " · " + T("latency.noreply")
			}
		}
		items[i] = it
	}
	s.Items = items
	return s
}
