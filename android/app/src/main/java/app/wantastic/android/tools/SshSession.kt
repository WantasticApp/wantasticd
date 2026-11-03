package app.wantastic.android.tools

import com.jcraft.jsch.ChannelShell
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.OutputStream
import kotlin.concurrent.thread

/**
 * An SSH shell to a device in the network, through the tunnel. Host keys are
 * trusted on first use and kept (known_hosts in the app's private folder), so
 * a changed key is refused, as with ssh. The password is never stored.
 */
class SshSession(private val knownHosts: File) {
    private var session: Session? = null
    private var channel: ChannelShell? = null
    private var out: OutputStream? = null

    suspend fun connect(
        host: String, port: Int, user: String, password: String, cols: Int, rows: Int,
        onOutput: (ByteArray, Int) -> Unit, onClosed: (String?) -> Unit,
    ) = withContext(Dispatchers.IO) {
        knownHosts.parentFile?.mkdirs()
        if (!knownHosts.exists()) knownHosts.createNewFile()
        val jsch = JSch().apply { setKnownHosts(knownHosts.path) }
        val s = jsch.getSession(user, host, port).apply {
            setPassword(password)
            setConfig("StrictHostKeyChecking", "accept-new")
            setConfig("PreferredAuthentications", "password,keyboard-interactive")
            setServerAliveInterval(15_000)
        }
        s.connect(15_000)
        val ch = (s.openChannel("shell") as ChannelShell).apply {
            setPtyType("xterm-256color")
            setPtySize(cols, rows, 0, 0)
        }
        val input = ch.inputStream
        out = ch.outputStream
        ch.connect(10_000)
        session = s
        channel = ch
        thread(name = "ssh-read", isDaemon = true) {
            val buf = ByteArray(16 * 1024)
            val reason = runCatching {
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    if (n > 0) onOutput(buf, n)
                }
            }.exceptionOrNull()?.message
            onClosed(reason)
        }
    }

    fun send(bytes: ByteArray) {
        runCatching { out?.apply { write(bytes); flush() } }
    }

    fun resize(cols: Int, rows: Int) {
        runCatching { channel?.setPtySize(cols, rows, 0, 0) }
    }

    fun close() {
        runCatching { channel?.disconnect() }
        runCatching { session?.disconnect() }
        channel = null; session = null; out = null
    }
}
