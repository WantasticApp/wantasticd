package app.wantastic.android.update

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException

class BsPatchTest {
    @get:Rule
    val tmp = TemporaryFolder()

    /** One bsdiff control triple: add [diff] to old bytes, copy [extra] verbatim, then move the old position by [seek]. */
    private class Step(val diff: ByteArray, val extra: ByteArray, val seek: Long)

    private fun offt(v: Long): ByteArray {
        var y = if (v < 0) -v else v
        val b = ByteArray(8)
        for (i in 0 until 8) { b[i] = (y and 0xff).toByte(); y = y shr 8 }
        if (v < 0) b[7] = (b[7].toInt() or 0x80).toByte()
        return b
    }

    private fun bz(b: ByteArray): ByteArray = ByteArrayOutputStream().also { o -> BZip2CompressorOutputStream(o).use { it.write(b) } }.toByteArray()

    /** Writes a BSDIFF40 patch exactly as bsdiff lays it out. */
    private fun patch(newSize: Int, steps: List<Step>): ByteArray {
        val ctrl = ByteArrayOutputStream(); val diff = ByteArrayOutputStream(); val extra = ByteArrayOutputStream()
        for (s in steps) {
            ctrl.write(offt(s.diff.size.toLong())); ctrl.write(offt(s.extra.size.toLong())); ctrl.write(offt(s.seek))
            diff.write(s.diff); extra.write(s.extra)
        }
        val c = bz(ctrl.toByteArray()); val d = bz(diff.toByteArray()); val e = bz(extra.toByteArray())
        return ByteArrayOutputStream().apply {
            write("BSDIFF40".toByteArray()); write(offt(c.size.toLong())); write(offt(d.size.toLong())); write(offt(newSize.toLong()))
            write(c); write(d); write(e)
        }.toByteArray()
    }

    private fun run(old: ByteArray, patch: ByteArray): ByteArray {
        val o = tmp.newFile().apply { writeBytes(old) }
        val p = tmp.newFile().apply { writeBytes(patch) }
        val out = File(tmp.root, "out-${System.nanoTime()}")
        BsPatch.apply(o, p, out)
        return out.readBytes()
    }

    @Test
    fun rebuildsTheNewFileFromOldPlusPatch() {
        val old = ByteArray(4096) { (it * 31).toByte() }
        val expected = old.copyOf(4096 + 5).also {
            it[10] = 7; it[2000] = (it[2000] + 1).toByte() // changed bytes
            "hello".toByteArray().copyInto(it, 4096)       // new tail
        }
        // Bytes 0..4095 as old + difference, then 5 new bytes.
        val diff = ByteArray(4096) { (expected[it] - old[it]).toByte() }
        val out = run(old, patch(expected.size, listOf(Step(diff, "hello".toByteArray(), 0))))
        assertArrayEquals(expected, out)
    }

    @Test
    fun followsNegativeSeeks() {
        val old = "ABCDEFGH".toByteArray()
        // "ABCD", then jump back to the start and take "AB" again: "ABCDAB".
        val steps = listOf(Step(ByteArray(4), ByteArray(0), -4), Step(ByteArray(2), ByteArray(0), 0))
        assertArrayEquals("ABCDAB".toByteArray(), run(old, patch(6, steps)))
    }

    @Test
    fun rejectsWhatIsNotAPatch() {
        assertThrows(IOException::class.java) { run(ByteArray(10), ByteArray(40) { 1 }) }
    }
}
