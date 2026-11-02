module wantastic-agent/mobile

go 1.26.0

require (
	golang.org/x/mobile v0.0.0-20261011034528-197770444867
	wantastic-agent v0.0.0
)

require (
	github.com/denisbrodbeck/machineid v1.0.1 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/mdp/qrterminal/v3 v3.2.1 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/term v0.42.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	rsc.io/qr v0.2.0 // indirect
)

// The agent itself, from this repository: the app runs the same code.
replace wantastic-agent => ../
