# Desktop visual verification

These captures are deterministic 420 x 680 visual fixtures for the frameless
tray window. They use synthetic preview data and never load local credentials.

- `devices.png` verifies the connected header, local device, tab navigation,
  searchable tenant device list, and direct/relay/offline states.
- `network.png` verifies MagicDNS, exit-node offering, and local-network route
  entry (including the `/32` host-route affordance).
- `detail.png` verifies the separate peer detail surface, P2P state, ping, exit
  node selection, and copy-IP action.
- `settings.png` verifies the worst-case compact settings layout with a claim
  result, manual configuration, and console action visible without scrolling.
- `offline.png` verifies the red disconnected side of the branded rocker while
  keeping status text explicit and free of coloured status dots.
- `loading.png` verifies the centered Wantastic flip animation and progress
  treatment used while the privileged tunnel helper is starting.

Regenerate them from the frontend development server with the explicit
`?preview=1` query parameter. Production and normal development URLs do not
enable preview data.
