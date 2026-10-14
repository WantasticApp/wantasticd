# Wantastic P2P Benchmark

This document showcases the performance capabilities of the **Wantastic** client. Using our native **TUN interface** routing, we achieve multi-gigabit speeds directly between clients over a seamless peer-to-peer connection.

The following are direct throughput test results (using `iperf3`) over the `wantastic0` TUN interface.

---

## Container-to-Container Direct P2P (Native TUN)
These tests benchmark the true speed between two Linux containers connected over Wantastic. Both containers route traffic directly through their native `wantastic0` kernel TUN interfaces.

### Client 1 (10.0.0.2) ➔ Client 2 (10.0.0.3)
```bash
docker exec wantasticd-client1 iperf3 -c 10.0.0.3 -p 5201 -t 10
```

**Result:** **2.72 Gbits/sec** ✨

<details>
<summary>Click to view full iperf3 output</summary>

```
Connecting to host 10.0.0.3, port 5201
[  6] local 10.0.0.2 port 55926 connected to 10.0.0.3 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  6]   0.00-1.00   sec   241 MBytes  2.02 Gbits/sec    0   4.11 MBytes       
[  6]   1.00-2.00   sec   288 MBytes  2.42 Gbits/sec    0   4.11 MBytes       
[  6]   2.00-3.00   sec   343 MBytes  2.88 Gbits/sec    0   4.11 MBytes       
[  6]   3.00-4.00   sec   348 MBytes  2.92 Gbits/sec    0   4.11 MBytes       
[  6]   4.00-5.00   sec   339 MBytes  2.84 Gbits/sec    0   4.11 MBytes       
[  6]   5.00-6.00   sec   280 MBytes  2.35 Gbits/sec    0   4.11 MBytes       
[  6]   6.00-7.00   sec   346 MBytes  2.90 Gbits/sec    0   4.11 MBytes       
[  6]   7.00-8.00   sec   348 MBytes  2.92 Gbits/sec    0   4.11 MBytes       
[  6]   8.00-9.00   sec   356 MBytes  2.98 Gbits/sec    0   4.11 MBytes       
[  6]   9.00-10.00  sec   352 MBytes  2.95 Gbits/sec    0   4.11 MBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  6]   0.00-10.00  sec  3.16 GBytes  2.72 Gbits/sec    0             sender
[  6]   0.00-10.01  sec  3.16 GBytes  2.72 Gbits/sec                  receiver
```
</details>

### Client 1 (10.0.0.2) ➔ Client 3 (10.0.0.4)
```bash
docker exec wantasticd-client1 iperf3 -c 10.0.0.4 -p 5201 -t 10
```

**Result:** **2.26 Gbits/sec** ✨

<details>
<summary>Click to view full iperf3 output</summary>

```
Connecting to host 10.0.0.4, port 5201
[  6] local 10.0.0.2 port 44242 connected to 10.0.0.4 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  6]   0.00-1.00   sec   278 MBytes  2.33 Gbits/sec    0   4.15 MBytes       
[  6]   1.00-2.00   sec   300 MBytes  2.51 Gbits/sec    0   4.15 MBytes       
[  6]   2.00-3.00   sec   294 MBytes  2.47 Gbits/sec    0   4.15 MBytes       
[  6]   3.00-4.00   sec   313 MBytes  2.62 Gbits/sec    0   4.15 MBytes       
[  6]   4.00-5.00   sec   331 MBytes  2.77 Gbits/sec    0   4.15 MBytes       
[  6]   5.00-6.00   sec   240 MBytes  2.01 Gbits/sec    0   4.15 MBytes       
[  6]   6.00-7.00   sec   247 MBytes  2.07 Gbits/sec    0   4.15 MBytes       
[  6]   7.00-8.00   sec   200 MBytes  1.68 Gbits/sec    0   4.15 MBytes       
[  6]   8.00-9.00   sec   254 MBytes  2.13 Gbits/sec    0   4.15 MBytes       
[  6]   9.00-10.01  sec   232 MBytes  1.93 Gbits/sec    0   4.15 MBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  6]   0.00-10.01  sec  2.63 GBytes  2.26 Gbits/sec    0             sender
[  6]   0.00-10.01  sec  2.63 GBytes  2.26 Gbits/sec                  receiver
```
</details>
