package app.wantastic.android.update

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.File
import java.io.IOException

/**
 * Applies a classic bsdiff patch (BSDIFF40, as made by `bsdiff old new patch`):
 * the new APK is the installed one plus the patch. The caller still checks
 * the result's SHA-256, so a bad patch can never install.
 */
object BsPatch {
    private const val HEADER = 32
    private const val MAX_SIZE = 512L * 1024 * 1024

    fun apply(old: File, patch: File, out: File) {
        val oldBytes = old.readBytes()
        val patchBytes = patch.readBytes()
        if (patchBytes.size < HEADER || String(patchBytes, 0, 8, Charsets.US_ASCII) != "BSDIFF40") {
            throw IOException("not a bsdiff patch")
        }
        val ctrlLen = offtin(patchBytes, 8)
        val diffLen = offtin(patchBytes, 16)
        val newSize = offtin(patchBytes, 24)
        if (ctrlLen < 0 || diffLen < 0 || newSize < 0 || newSize > MAX_SIZE ||
            HEADER + ctrlLen + diffLen > patchBytes.size
        ) throw IOException("corrupt patch header")

        fun block(from: Long, len: Long) =
            DataInputStream(BZip2CompressorInputStream(ByteArrayInputStream(patchBytes, from.toInt(), len.toInt())))
        val ctrl = block(HEADER.toLong(), ctrlLen)
        val diff = block(HEADER + ctrlLen, diffLen)
        val extra = block(HEADER + ctrlLen + diffLen, patchBytes.size - HEADER - ctrlLen - diffLen)

        val new = ByteArray(newSize.toInt())
        val word = ByteArray(8)
        fun next(): Long { ctrl.readFully(word); return offtin(word, 0) }
        var newPos = 0
        var oldPos = 0L
        while (newPos < newSize) {
            val add = next()
            val copy = next()
            val seek = next()
            if (add < 0 || copy < 0 || newPos + add + copy > newSize) throw IOException("corrupt patch control")
            diff.readFully(new, newPos, add.toInt())
            for (i in 0 until add.toInt()) {
                val o = oldPos + i
                if (o >= 0 && o < oldBytes.size) new[newPos + i] = (new[newPos + i] + oldBytes[o.toInt()]).toByte()
            }
            newPos += add.toInt()
            oldPos += add
            extra.readFully(new, newPos, copy.toInt())
            newPos += copy.toInt()
            oldPos += seek
        }
        out.writeBytes(new)
    }

    /** bsdiff's 64-bit sign-magnitude little-endian integer. */
    private fun offtin(b: ByteArray, at: Int): Long {
        var y = (b[at + 7].toLong() and 0x7f)
        for (i in 6 downTo 0) y = (y shl 8) or (b[at + i].toLong() and 0xff)
        return if (b[at + 7].toInt() and 0x80 != 0) -y else y
    }
}
