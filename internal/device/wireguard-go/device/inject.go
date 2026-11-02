package device

// InjectOutbound encrypts and sends a plaintext IP packet to the peer whose
// allowed IPs hold its destination, exactly as if it had been read from the
// TUN. The userspace exit-node stack uses it to return internet replies to
// peers without a kernel NAT. It reports whether the packet was queued.
func (device *Device) InjectOutbound(packet []byte) (ok bool) {
	// The device may be closing: its encryption queue is then closed under
	// us. Callers outside the device's own routines must not crash it.
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if len(packet) == 0 || len(packet) > MaxContentSize {
		return false
	}
	var dst []byte
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < IPv4offsetDst+4 {
			return false
		}
		dst = packet[IPv4offsetDst : IPv4offsetDst+4]
	case 6:
		if len(packet) < IPv6offsetDst+16 {
			return false
		}
		dst = packet[IPv6offsetDst : IPv6offsetDst+16]
	default:
		return false
	}
	peer := device.allowedips.Lookup(dst)
	if peer == nil || !peer.isRunning.Load() {
		return false
	}
	elem := device.NewOutboundElement()
	n := copy(elem.buffer[MessageTransportHeaderSize:], packet)
	elem.packet = elem.buffer[MessageTransportHeaderSize : MessageTransportHeaderSize+n]
	elems := device.GetOutboundElementsContainer()
	elems.elems = append(elems.elems, elem)
	peer.StagePackets(elems)
	peer.SendStagedPackets()
	return true
}
