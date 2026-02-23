# wantasticd
wantastic custom userspace wireguard client daemon

# Installation
## Linux
No prerequisites required.
```
wget https://github.com/wantastic/wantasticd/releases/download/${VERSION}/wantasticd-linux-${ARCH}
chmod +x wantasticd-linux-${ARCH}
sudo mv wantasticd-linux-${ARCH} /usr/local/bin/wantasticd
```
## connect
To connect to a WireGuard server, use the `connect` command.
```
wantasticd connect -config /etc/wireguard/wg0.conf
```
## status
To check the status of the WireGuard connection, use the `status` command.
```
wantasticd status
```
## login
wantasticd login -token ${TOKEN}
## login with console.wantastic.app
To  login with console.wantastic.app, use the `login` command without any flags.
```
wantasticd login   
```
## service mode
To install the service, use the `install` command.
```
wantasticd install -config /etc/wireguard/wg0.conf
```
To uninstall the service, use the `uninstall` command.
```
wantasticd uninstall
```
To start the service, use the `start` command.
```
wantasticd start
```
To stop the service, use the `stop` command.
```
wantasticd stop
```
To restart the service, use the `restart` command.
```
wantasticd restart
```
To check the status of the service, use the `status` command.
```
wantasticd status

# P2P Test
```bash
./e2e/run_p2p_test.sh
```
# P2P Benchmark
```bash
==> Ensuring wantasticd clients are running...
==> Waiting 5 seconds for tunnels to establish handshakes and P2P connections...
==========================================
     WIREGUARD TUNNEL STATUS (P2P PROOF)  
==========================================
--- Client1 Status ---
=== WireGuard Userspace Device Status ===
  Local Address: 10.0.0.3/32
  Listen Port:   55507
  Hub Endpoint:  0.250.250.254 (configured)
  Peers:         3

  Peer #1
    Public Key:  nCwnKpc6y7/Efkhjlw7Pk+b1t8bBxhND7wpa+O4DBHE=
    Endpoint:    0.250.250.254:51820
    Mode:        🔄 VPN/Relay (via Hub)
    Handshake:   5s ago (03:15:01)
    Transfer:    ↓ 30.27 KiB received, ↑ 51.77 KiB sent
    Allowed IPs: 10.0.0.0/27

  Peer #2
    Public Key:  tvrJJGsuioRzSbS7zLgRI3/n3TIPohywt//T0MlEEzo=
    Endpoint:    172.25.0.13:48050
    Mode:        ⚡ P2P Direct (hole-punched)
    Handshake:   1m55s ago (03:13:11)
    Transfer:    ↓ 1.26 KiB received, ↑ 4.24 KiB sent
    Allowed IPs: 10.0.0.5/32

  Peer #3
    Public Key:  9gz1VX7kkUvnWAV8jCv9c4hgfDhRpXo+lwilOytQPQ0=
    Endpoint:    172.25.0.12:33606
    Mode:        ⚡ P2P Direct (hole-punched)
    Handshake:   2m0s ago (03:13:06)
    Transfer:    ↓ 3.79 KiB received, ↑ 5.75 KiB sent
    Allowed IPs: 10.0.0.4/32


--- Client2 Status ---
=== WireGuard Userspace Device Status ===
  Local Address: 10.0.0.4/32
  Listen Port:   33606
  Hub Endpoint:  0.250.250.254 (configured)
  Peers:         3

  Peer #1
    Public Key:  nCwnKpc6y7/Efkhjlw7Pk+b1t8bBxhND7wpa+O4DBHE=
    Endpoint:    0.250.250.254:51820
    Mode:        🔄 VPN/Relay (via Hub)
    Handshake:   5s ago (03:15:01)
    Transfer:    ↓ 6.98 KiB received, ↑ 30.16 KiB sent
    Allowed IPs: 10.0.0.0/27

  Peer #2
    Public Key:  tvrJJGsuioRzSbS7zLgRI3/n3TIPohywt//T0MlEEzo=
    Endpoint:    172.25.0.13:48050
    Mode:        ⚡ P2P Direct (hole-punched)
    Handshake:   1m46s ago (03:13:20)
    Transfer:    ↓ 1.60 KiB received, ↑ 2.49 KiB sent
    Allowed IPs: 10.0.0.5/32

  Peer #3
    Public Key:  Q8OF6WMu4fUrjj8t9NibZO7Qa6IVRfsifSUSjBhwjH0=
    Endpoint:    172.25.0.11:55507
    Mode:        ⚡ P2P Direct (hole-punched)
    Handshake:   2m0s ago (03:13:06)
    Transfer:    ↓ 3.68 KiB received, ↑ 5.85 KiB sent
    Allowed IPs: 10.0.0.3/32


==========================================
          LATENCY TESTS (PING)            
==========================================
PING from Client1 (10.0.0.3) -> Client2 (10.0.0.4)
PING 10.0.0.4 (10.0.0.4): via wantasticd netstack
64 bytes from 10.0.0.4: icmp_seq=1 time=2.116 ms
64 bytes from 10.0.0.4: icmp_seq=2 time=0.964 ms
64 bytes from 10.0.0.4: icmp_seq=3 time=2.410 ms
64 bytes from 10.0.0.4: icmp_seq=4 time=1.031 ms

--- 10.0.0.4 ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max = 0.964/1.630/2.410 ms

PING from Client1 (10.0.0.3) -> Client3 (10.0.0.5)
PING 10.0.0.5 (10.0.0.5): via wantasticd netstack
64 bytes from 10.0.0.5: icmp_seq=1 time=5.504 ms
64 bytes from 10.0.0.5: icmp_seq=2 time=1.040 ms
64 bytes from 10.0.0.5: icmp_seq=3 time=26.421 ms
64 bytes from 10.0.0.5: icmp_seq=4 time=14.017 ms

--- 10.0.0.5 ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max = 1.040/11.746/26.421 ms

==========================================
         THROUGHPUT TESTS (IPERF3)        
==========================================
Starting iperf3 servers on Client2 and Client3...
Binding Wantastic ports on Client1 to map into the Userspace Netstack via proxy...
...
IPERF3 from Client1 -> Client2 (P2P Over WireGuard Tunnel via IPC proxy)
Connecting to host 127.0.0.1, port 5201
[  6] local 127.0.0.1 port 59790 connected to 127.0.0.1 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  6]   0.00-1.00   sec  59.8 MBytes   501 Mbits/sec   10    639 KBytes       
[  6]   1.00-2.00   sec  77.5 MBytes   650 Mbits/sec    7    639 KBytes       
[  6]   2.00-3.00   sec  82.1 MBytes   688 Mbits/sec    6    639 KBytes       
[  6]   3.00-4.00   sec  85.8 MBytes   720 Mbits/sec    6    639 KBytes       
[  6]   4.00-5.00   sec  49.2 MBytes   413 Mbits/sec   14    639 KBytes       
[  6]   5.00-6.01   sec  53.1 MBytes   442 Mbits/sec   13    639 KBytes       
[  6]   6.01-7.00   sec  20.0 MBytes   169 Mbits/sec   16    639 KBytes       
[  6]   7.00-8.00   sec  11.2 MBytes  94.2 Mbits/sec    9    639 KBytes       
[  6]   8.00-9.00   sec  14.4 MBytes   121 Mbits/sec   13    639 KBytes       
[  6]   9.00-10.00  sec  18.5 MBytes   155 Mbits/sec    9    639 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  6]   0.00-10.00  sec   472 MBytes   396 Mbits/sec  103             sender
[  6]   0.00-10.02  sec   466 MBytes   390 Mbits/sec                  receiver

iperf Done.
...
IPERF3 from Client1 -> Client3 (P2P Over WireGuard Tunnel via IPC proxy)
Connecting to host 127.0.0.1, port 5202
[  6] local 127.0.0.1 port 49878 connected to 127.0.0.1 port 5202
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  6]   0.00-1.00   sec  10.9 MBytes  91.1 Mbits/sec    7    565 KBytes       
[  6]   1.00-2.00   sec  48.5 MBytes   407 Mbits/sec   14    639 KBytes       
[  6]   2.00-3.00   sec  75.9 MBytes   636 Mbits/sec   12    639 KBytes       
[  6]   3.00-4.00   sec  80.5 MBytes   676 Mbits/sec    6    639 KBytes       
[  6]   4.00-5.00   sec  88.1 MBytes   740 Mbits/sec    5    639 KBytes       
[  6]   5.00-6.01   sec  76.8 MBytes   641 Mbits/sec    5    639 KBytes       
[  6]   6.01-7.00   sec  65.0 MBytes   547 Mbits/sec   14    639 KBytes       
[  6]   7.00-8.00   sec  93.6 MBytes   786 Mbits/sec    8    448 KBytes       
[  6]   8.00-9.00   sec  89.4 MBytes   749 Mbits/sec    2    448 KBytes       
[  6]   9.00-10.00  sec  78.6 MBytes   658 Mbits/sec    6    448 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  6]   0.00-10.00  sec   707 MBytes   593 Mbits/sec   79             sender
[  6]   0.00-10.34  sec   704 MBytes   571 Mbits/sec                  receiver

iperf Done.
...
==========================================
    THROUGHPUT TESTS (NORMAL NETWORK)     
==========================================
IPERF3 from Client1 -> Client2 (Normal Docker Network)
Connecting to host 172.25.0.12, port 5201
[  6] local 172.25.0.11 port 55922 connected to 172.25.0.12 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  6]   0.00-1.00   sec  3.78 GBytes  32.5 Gbits/sec    2   1.07 MBytes       
[  6]   1.00-2.00   sec  4.15 GBytes  35.7 Gbits/sec    0   1.13 MBytes       
[  6]   2.00-3.00   sec  4.32 GBytes  37.1 Gbits/sec    1   1.21 MBytes       
[  6]   3.00-4.00   sec  5.19 GBytes  44.5 Gbits/sec    0   1.26 MBytes       
[  6]   4.00-5.00   sec  5.13 GBytes  44.1 Gbits/sec    0   1.34 MBytes       
[  6]   5.00-6.00   sec  5.23 GBytes  44.9 Gbits/sec    0   1.40 MBytes       
[  6]   6.00-7.00   sec  4.02 GBytes  34.6 Gbits/sec    0   1.47 MBytes       
[  6]   7.00-8.00   sec  4.76 GBytes  40.9 Gbits/sec    0   1.55 MBytes       
[  6]   8.00-9.03   sec  4.26 GBytes  35.4 Gbits/sec    1   1.61 MBytes       
[  6]   9.03-10.00  sec  4.05 GBytes  35.9 Gbits/sec    2   1.69 MBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  6]   0.00-10.00  sec  44.9 GBytes  38.6 Gbits/sec    6             sender
[  6]   0.00-10.00  sec  44.9 GBytes  38.6 Gbits/sec                  receiver

iperf Done.
...
IPERF3 from Client1 -> Client3 (Normal Docker Network)
Connecting to host 172.25.0.13, port 5201
[  6] local 172.25.0.11 port 35292 connected to 172.25.0.13 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  6]   0.00-1.00   sec  5.12 GBytes  43.9 Gbits/sec    0    505 KBytes       
[  6]   1.00-2.00   sec  4.02 GBytes  34.5 Gbits/sec    0    645 KBytes       
[  6]   2.00-3.00   sec  5.17 GBytes  44.3 Gbits/sec    0    677 KBytes       
[  6]   3.00-4.00   sec  5.01 GBytes  43.1 Gbits/sec    0    956 KBytes       
[  6]   4.00-5.00   sec  4.88 GBytes  41.9 Gbits/sec    0    956 KBytes       
[  6]   5.00-6.01   sec  4.90 GBytes  42.0 Gbits/sec    0    956 KBytes       
[  6]   6.01-7.00   sec  5.20 GBytes  44.8 Gbits/sec    0    956 KBytes       
[  6]   7.00-8.00   sec  4.74 GBytes  40.7 Gbits/sec    0    956 KBytes       
[  6]   8.00-9.00   sec  4.92 GBytes  42.2 Gbits/sec    0    956 KBytes       
[  6]   9.00-10.00  sec  5.22 GBytes  44.8 Gbits/sec    0    956 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  6]   0.00-10.00  sec  49.2 GBytes  42.2 Gbits/sec    0             sender
[  6]   0.00-10.00  sec  49.2 GBytes  42.2 Gbits/sec                  receiver

iperf Done.
==========================================
            CLEANUP                       
==========================================
Killing background tasks...
E2E P2P Test Finished Successfully!
```