package app.wantastic.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class DeviceTest {
    /** A tunnel interface in memory: what the phone "sends" and what arrives. */
    class MemTun : TunIo {
        val toEngine = LinkedBlockingQueue<ByteArray>()
        val fromEngine = LinkedBlockingQueue<ByteArray>()
        @Volatile var closed = false
        override fun read(buf: ByteArray): Int {
            while (!closed) {
                val p = toEngine.poll(100, TimeUnit.MILLISECONDS) ?: continue
                p.copyInto(buf)
                return p.size
            }
            return -1
        }
        override fun write(buf: ByteArray, len: Int) { fromEngine.put(buf.copyOf(len)) }
        override fun close() { closed = true }
    }

    private fun ipv4(src: String, dst: String, payload: ByteArray): ByteArray {
        val p = ByteArray(20 + payload.size)
        p[0] = 0x45
        val len = p.size
        p[2] = (len ushr 8).toByte(); p[3] = len.toByte()
        p[8] = 64; p[9] = 17
        InetAddress.getByName(src).address.copyInto(p, 12)
        InetAddress.getByName(dst).address.copyInto(p, 16)
        payload.copyInto(p, 20)
        return p
    }

    @Test fun twoDevicesHandshakeAndCarryPackets() {
        val aPriv = WgCrypto.generatePrivateKey()
        val bPriv = WgCrypto.generatePrivateKey()
        val aTun = MemTun()
        val bTun = MemTun()
        // b answers only (no keepalive of its own); its endpoint is learnt from a.
        val b = WireGuardDevice(
            TunnelConfig(bPriv, listOf(IpPrefix.parse("10.0.0.2/32")!!), emptyList(), 1420,
                PeerConfig(WgCrypto.publicKey(aPriv), "127.0.0.1", 9, listOf(IpPrefix.parse("10.0.0.1/32")!!), 0)),
            bTun,
        )
        b.start()
        val a = WireGuardDevice(
            TunnelConfig(aPriv, listOf(IpPrefix.parse("10.0.0.1/32")!!), emptyList(), 1420,
                PeerConfig(WgCrypto.publicKey(bPriv), "127.0.0.1", b.localPort, listOf(IpPrefix.parse("10.0.0.0/24")!!), 25)),
            aTun,
        )
        a.start()
        try {
            // Persistent keepalive makes a handshake right away.
            val deadline = System.currentTimeMillis() + 5000
            while (a.stats.lastHandshakeMs == 0L && System.currentTimeMillis() < deadline) Thread.sleep(20)
            assertTrue("handshake completes", a.stats.lastHandshakeMs > 0)

            val out = ipv4("10.0.0.1", "10.0.0.2", "ping from a".toByteArray())
            aTun.toEngine.put(out)
            val got = bTun.fromEngine.poll(3, TimeUnit.SECONDS)
            assertNotNull("b receives a's packet", got)
            assertArrayEquals("padding is removed", out, got)

            val back = ipv4("10.0.0.2", "10.0.0.1", "pong from b, a little longer".toByteArray())
            bTun.toEngine.put(back)
            assertArrayEquals(back, aTun.fromEngine.poll(3, TimeUnit.SECONDS))

            // A packet from an address b does not allow for a is dropped.
            aTun.toEngine.put(ipv4("10.0.0.9", "10.0.0.2", "spoofed".toByteArray()))
            assertEquals(null, bTun.fromEngine.poll(500, TimeUnit.MILLISECONDS))
        } finally {
            a.stop()
            b.stop()
        }
    }

    @Test fun configFromClaim() {
        val priv = base64Encode(WgCrypto.generatePrivateKey())
        val server = base64Encode(WgCrypto.publicKey(WgCrypto.generatePrivateKey()))
        val c = TunnelConfig.fromClaim(priv, """{"claimed":true,"server_key":"$server","assigned_ip":"10.6.84.194/32",
            "endpoint":"wg.wantastic.app:51820","allowed_ips":["10.6.84.192/27"],"dns_servers":["10.6.84.193"]}""")
        assertEquals("wg.wantastic.app", c.server.endpointHost)
        assertEquals(51820, c.server.endpointPort)
        assertEquals(1420, c.mtu)
        assertEquals(25, c.server.persistentKeepaliveSec)
        assertEquals("10.6.84.192/27", c.server.allowedIps.single().toString())
        assertTrue(c.server.allowedIps.single().contains(InetAddress.getByName("10.6.84.200").address))
        val noPort = TunnelConfig.fromClaim(priv, """{"server_key":"$server","assigned_ip":"10.0.0.2","endpoint":"hub.example","listen_port":0}""")
        assertEquals(51820, noPort.server.endpointPort)
    }
}
