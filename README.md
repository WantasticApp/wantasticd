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
Check out our [P2P Performance Benchmarks](./p2pbenchmark.md) to see the multi-gigabit throughput capabilities of the new Wantastic Userspace Hybrid Netstack!