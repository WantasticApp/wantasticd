module wantastic-agent/mobile

go 1.26.0

require (
	golang.org/x/mobile v0.0.0-20261011034528-197770444867
	wantastic-agent v0.0.0
)

require (
	github.com/bgptools/mndp v0.0.0-20231212115012-3273940ea35e // indirect
	github.com/denisbrodbeck/machineid v1.0.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/honeybbq/goubus v1.4.0 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/maltegrosse/go-modemmanager v0.1.4 // indirect
	github.com/mdlayher/ethernet v0.0.0-20220221185849-529eae5b6118 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/lldp v0.0.0-20150915211757-afd9f83164c5 // indirect
	github.com/mdlayher/netlink v1.8.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/mdlayher/wifi v0.7.2 // indirect
	github.com/mdp/qrterminal/v3 v3.2.1 // indirect
	github.com/showwin/speedtest-go v1.7.11 // indirect
	github.com/stratoberry/go-gpsd v1.3.0 // indirect
	github.com/warthog618/sms v0.3.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
	rsc.io/qr v0.2.0 // indirect
)

// The agent itself, from this repository: the app runs the same code.
replace wantastic-agent => ../
