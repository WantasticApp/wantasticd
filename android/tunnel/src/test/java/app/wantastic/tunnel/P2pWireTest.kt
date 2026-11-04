package app.wantastic.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.InetAddress
import java.net.InetSocketAddress

/** Bytes the Go agent produced for the same inputs: the wire formats must match exactly. */
class P2pWireTest {
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private fun sa(ip: String, port: Int) = InetSocketAddress(InetAddress.getByName(ip), port)

    private val privA = hex("0002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f60")
    private val privB = hex("6065666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818243")

    @Test fun messageMatchesGo() {
        assertArrayEquals("X25519 public key", hex("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"), WgCrypto.publicKey(privA))
        val msg = P2pMessage(
            P2pClient.SUBTYPE_REGISTER, WgCrypto.publicKey(privA),
            local = sa("192.168.1.20", 51820), observed = sa("105.74.64.15", 40358),
            targetId = 0x01020304, nonce = byteArrayOf(9, 8, 7, 6, 5, 4, 3, 2),
            payload = P2pClient.encodeCandidates(listOf(sa("192.168.1.20", 51820), sa("196.64.53.172", 51491))),
        )
        assertArrayEquals("P2PMessage.Encode", hex("0100000007a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c00000000000000000000ffffc0a80114ca6c00000000000000000000ffff694a400f9da6010203040908070605040302575043310200000000000000000000ffffc0a80114ca6c00000000000000000000ffffc44035acc923"), msg.encode())
        assertArrayEquals("control frame", hex("575043017d000100000007a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c00000000000000000000ffffc0a80114ca6c00000000000000000000ffff694a400f9da6010203040908070605040302575043310200000000000000000000ffffc0a80114ca6c00000000000000000000ffffc44035acc923"), WireGuardDevice.frameControl(msg.encode()))

        val back = P2pMessage.decode(msg.encode())!!
        assertEquals(sa("105.74.64.15", 40358), back.observed)
        assertEquals(0x01020304, back.targetId)
        assertEquals(listOf(sa("192.168.1.20", 51820), sa("196.64.53.172", 51491)), P2pClient.decodeCandidates(back.payload, 0))
        assertArrayEquals(msg.encode(), WireGuardDevice.unframeControl(WireGuardDevice.frameControl(msg.encode()) + ByteArray(3)))
    }

    @Test fun punchMacMatchesGo() {
        val ss = WgCrypto.dh(privA, WgCrypto.publicKey(privB))
        assertArrayEquals(hex("2fb4b03c0d1abb77442634159fbb41ce5d5feee17dd94bae2d5c44827f14041b"), Blake2s(32, ss).update(byteArrayOf(9, 8, 7, 6, 5, 4, 3, 2)).digest())
    }
}
