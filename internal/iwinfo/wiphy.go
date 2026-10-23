package iwinfo

// WiphyChannel is one 20 MHz channel a radio can tune to, as the kernel's
// regulatory state allows it right now.
type WiphyChannel struct {
	Channel     int
	Frequency   int // MHz
	MaxPowerDBM int // regulatory and hardware limit, 0 when unknown
	Disabled    bool
	NoIR        bool // passive only: no initiating radiation (beaconing) allowed
	Radar       bool // DFS channel
}

// WiphyBand is one frequency band of a radio with the channel widths its
// HT/VHT/HE/EHT capabilities allow there.
type WiphyBand struct {
	Band     string // TR-181 band: 2.4GHz, 5GHz, 6GHz, 60GHz
	Channels []WiphyChannel
	HT       bool
	VHT      bool
	HE       bool
	EHT      bool
	Widths   []int // supported operating widths in MHz, ascending
}

// Wiphy is a radio's capability set (NL80211_CMD_GET_WIPHY).
type Wiphy struct {
	Index int
	Bands []WiphyBand
}

// Band returns the named band, or nil when the radio does not support it.
func (w *Wiphy) Band(name string) *WiphyBand {
	if w == nil {
		return nil
	}
	for i := range w.Bands {
		if w.Bands[i].Band == name {
			return &w.Bands[i]
		}
	}
	return nil
}

// BandNames lists the supported bands in ascending frequency order.
func (w *Wiphy) BandNames() []string {
	if w == nil {
		return nil
	}
	out := make([]string, 0, len(w.Bands))
	for _, band := range w.Bands {
		out = append(out, band.Band)
	}
	return out
}

// UsableChannels returns the channels that may be configured (not disabled).
func (b *WiphyBand) UsableChannels() []WiphyChannel {
	if b == nil {
		return nil
	}
	out := make([]WiphyChannel, 0, len(b.Channels))
	for _, channel := range b.Channels {
		if !channel.Disabled && channel.Channel > 0 {
			out = append(out, channel)
		}
	}
	return out
}

// MaxPowerDBM is the highest transmit power any usable channel allows.
func (b *WiphyBand) MaxPowerDBM() int {
	best := 0
	for _, channel := range b.UsableChannels() {
		best = max(best, channel.MaxPowerDBM)
	}
	return best
}

// ChannelPowerDBM is the limit on one channel, falling back to the band max.
func (b *WiphyBand) ChannelPowerDBM(channel int) int {
	for _, entry := range b.UsableChannels() {
		if entry.Channel == channel && entry.MaxPowerDBM > 0 {
			return entry.MaxPowerDBM
		}
	}
	return b.MaxPowerDBM()
}

// FrequencyChannel maps a center frequency in MHz to its IEEE channel number.
func FrequencyChannel(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5
	case mhz == 5935:
		return 2
	case mhz >= 5955 && mhz <= 7115:
		return (mhz - 5950) / 5
	case mhz >= 4910 && mhz <= 5895:
		return (mhz - 5000) / 5
	case mhz >= 58320 && mhz <= 70200:
		return (mhz - 56160) / 2160
	}
	return 0
}
