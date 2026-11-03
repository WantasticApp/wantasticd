package app.wantastic.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NoiseTest {
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    @Test fun blake2sVectors() {
        // RFC 7693 appendix B
        assertArrayEquals(hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"), WgCrypto.hash("abc".toByteArray()))
        // blake2s-kat.txt: keyed, key 00..1f, empty input
        val key = ByteArray(32) { it.toByte() }
        assertArrayEquals(hex("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"), Blake2s(32, key).digest())
        // ...and input 00 (second KAT entry)
        assertArrayEquals(hex("40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"), Blake2s(32, key).update(byteArrayOf(0)).digest())
        // Streaming in odd pieces equals one shot, across block boundaries.
        val data = ByteArray(1000) { (it * 7).toByte() }
        val oneShot = WgCrypto.hash(data)
        val pieces = Blake2s().update(data, 0, 63).update(data, 63, 1).update(data, 64, 500).update(data, 564, 436).digest()
        assertArrayEquals(oneShot, pieces)
    }

    private fun keys(): Pair<ByteArray, ByteArray> = WgCrypto.generatePrivateKey().let { it to WgCrypto.publicKey(it) }

    @Test fun handshakeBothWaysAndTransport() {
        val (aPriv, aPub) = keys()
        val (bPriv, bPub) = keys()
        val a = Handshake(aPriv, aPub, bPub)
        val b = Handshake(bPriv, bPub, aPub)

        val init = a.createInitiation(0x11223344)
        assertEquals(MessageType.INITIATION_SIZE, init.size)
        assertTrue(b.consumeInitiation(init))
        assertFalse("a replayed initiation is refused", b.consumeInitiation(init))
        val (resp, bKeys) = b.createResponse(0x55667788)!!
        assertEquals(MessageType.RESPONSE_SIZE, resp.size)
        val aKeys = a.consumeResponse(resp)
        assertNotNull(aKeys)
        aKeys!!
        assertArrayEquals(aKeys.sendKey, bKeys.receiveKey)
        assertArrayEquals(aKeys.receiveKey, bKeys.sendKey)
        assertEquals(0x55667788, aKeys.remoteIndex)
        assertEquals(0x11223344, bKeys.remoteIndex)
        assertNull("one response per initiation", a.consumeResponse(resp))

        val plain = "hello through the tunnel".toByteArray()
        val c = aKeys.nextCounter()
        val sealed = WgCrypto.seal(aKeys.sendKey, c, plain, ByteArray(0))
        assertArrayEquals(plain, WgCrypto.open(bKeys.receiveKey, c, sealed, ByteArray(0)))
        sealed[3] = (sealed[3].toInt() xor 1).toByte()
        assertNull("tampering is detected", WgCrypto.open(bKeys.receiveKey, c, sealed, ByteArray(0)))
    }

    @Test fun wrongResponderKeyFails() {
        val (aPriv, aPub) = keys()
        val (_, bPub) = keys()
        val (cPriv, cPub) = keys()
        val a = Handshake(aPriv, aPub, bPub)
        val c = Handshake(cPriv, cPub, aPub) // not the peer a is talking to
        assertFalse(c.consumeInitiation(a.createInitiation(1)))
    }

    @Test fun replayWindow() {
        val r = ReplayFilter()
        assertTrue(r.check(0))
        assertFalse(r.check(0))
        assertTrue(r.check(5))
        assertTrue(r.check(3))
        assertFalse(r.check(3))
        assertTrue(r.check(5000))
        assertFalse("far behind the window", r.check(10))
        assertTrue(r.check(4990))
        assertFalse(r.check(4990))
    }
}
