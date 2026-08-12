# OpenWrt Wi-Fi stations and IP neighbors

Linux `ip link`/rtnetlink can enumerate network links, but it does not expose
802.11 association state. WantasticD therefore uses the Wi-Fi interface names
reported by `network.wireless status` (with UCI as a fallback) and collects
station state from the Wi-Fi control plane.

## Station collection order

The OpenWrt backend merges these sources by station MAC address:

1. `device.getStaList`, when a vendor firmware provides that extension.
2. `hostapd.<ifname>.get_clients`, the stock OpenWrt `wpad`/hostapd ubus API.
3. `github.com/mdlayher/wifi` nl80211 station and survey dumps in normal pure-Go
   Linux builds, or `libiwinfo` when built with `-tags iwinfo`.
4. Linux debugfs only as the final pure-Go fallback for a driver without a
   working nl80211 station dump.

The hostapd call supplies association/authentication state and negotiated Wi-Fi
generation. nl80211/libiwinfo supplies the detailed counters, rates, connection
time, retry/failure counts, average signal, and channel noise. Merging avoids
discarding useful fields when a driver omits part of either response.

Collected stations populate:

- `Device.WiFi.AccessPoint.{i}.AssociatedDeviceNumberOfEntries`
- `Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.MACAddress`
- authentication, active state, operating standard, association time, signal,
  noise, SNR, last uplink/downlink rates, and available packet/byte/retry/error
  counters under the standard TR-181 associated-device object
- `Device.Hosts.Host.{i}` rows linked through `AssociatedDevice`

IP neighbors are merged into the same host rows from DHCP leases,
`/proc/net/arp`, and `ip neigh show`, which covers both ARP and IPv6 NDP cache
entries. An associated station remains visible as a host even before it has a
DHCP lease or neighbor-cache entry.

## OpenWrt availability

The normal `wpad`/hostapd service provides `hostapd.<ifname>.get_clients`; it
does not require `rpcd-mod-iwinfo`. mac80211-based drivers also expose nl80211,
so the default `CGO_ENABLED=0` embedded build can collect stations without an
extra shared library. The agent needs sufficient privileges to query the
wireless interface (the procd service normally runs as root).

`libiwinfo` remains useful for vendor Wi-Fi drivers which are not fully backed
by mac80211/nl80211. Build with `make build-iwinfo` on a target/toolchain that
provides `libiwinfo`. The optional `rpcd-mod-iwinfo` package exposes similar
information through the `iwinfo` ubus object, but it is not required by the
stock hostapd plus nl80211 path.

Useful on-device checks are:

```sh
ubus call network.wireless status
ubus call hostapd.phy0-ap0 get_clients
iw dev phy0-ap0 station dump
iwinfo phy0-ap0 assoclist
ip neigh show
```

Replace `phy0-ap0` with the `ifname` shown by `network.wireless status` (older
OpenWrt releases commonly use names such as `wlan0`). An empty hostapd `clients`
object and an empty `iw ... station dump` both mean that the AP currently has no
associated stations; an ubus “object not found” error instead indicates the
wrong interface name, a down AP, or a non-standard/minimal `wpad` build.
