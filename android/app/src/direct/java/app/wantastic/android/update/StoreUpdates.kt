package app.wantastic.android.update

import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import app.wantastic.android.BuildConfig
import app.wantastic.android.ACTION_INSTALL_UPDATE
import app.wantastic.android.MainActivity
import app.wantastic.android.R
import app.wantastic.android.settings.AppSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * The direct build updates itself from get.wantastic.app:
 *
 *   android/latest/update.json  {version, versionCode, apk{url,sha256,size}, patches[{from,url,sha256,size}]}
 *
 * A patch is offered when the installed APK's SHA-256 matches its "from";
 * otherwise the whole APK downloads. The result must match the published
 * SHA-256 and be signed with this app's key, or it is thrown away. Android
 * installs it; with Android 12+ and Wantastic as the installer of record no
 * confirmation is needed, otherwise Android asks once.
 */
class StoreUpdates(private val context: Context) : Updater {
    private val settings = AppSettings.get(context)
    private val state = MutableStateFlow<UpdateStatus>(UpdateStatus.Idle)
    override val status: StateFlow<UpdateStatus> = state.asStateFlow()
    override val selfUpdating = true
    private val lock = Mutex()
    private val dir = File(context.cacheDir, "updates")

    override suspend fun check(interactive: Boolean) = lock.withLock {
        withContext(Dispatchers.IO) {
            try {
                state.value = UpdateStatus.Checking
                // No feed yet (before the first release that publishes one): nothing to update to.
                val feed = fetch(MANIFEST) ?: run {
                    settings.lastUpdateCheck = System.currentTimeMillis()
                    state.value = UpdateStatus.UpToDate
                    return@withContext
                }
                val release = JSONObject(feed)
                settings.lastUpdateCheck = System.currentTimeMillis()
                val code = release.getLong("versionCode")
                val version = release.getString("version")
                if (code <= BuildConfig.VERSION_CODE) {
                    state.value = UpdateStatus.UpToDate
                    cleanup(keep = null)
                    return@withContext
                }
                state.value = UpdateStatus.Available(version)
                val allowed = interactive || (settings.autoUpdate.value && (!settings.wifiOnly.value || unmetered()))
                if (!allowed) return@withContext
                val apk = download(release, version, code)
                state.value = UpdateStatus.Ready(version)
                if (!interactive) installQuietly(apk, version)
            } catch (e: Exception) {
                Log.w(TAG, "update check failed", e)
                state.value = UpdateStatus.Failed(e.message ?: "Update failed")
            }
        }
    }

    override fun install(activity: Activity) {
        val ready = state.value as? UpdateStatus.Ready ?: return
        val apk = readyFile() ?: return
        state.value = UpdateStatus.Installing
        commit(apk, ready.version, foreground = true)
    }

    private fun download(release: JSONObject, version: String, code: Long): File {
        dir.mkdirs()
        val target = File(dir, "wantastic-$code.apk")
        val apk = release.getJSONObject("apk")
        val want = apk.getString("sha256").lowercase()
        if (target.exists() && sha256(target) == want) return target.also { cleanup(keep = it) }
        cleanup(keep = null)

        // A patch from exactly the APK installed here, when one exists.
        val installed = File(context.applicationInfo.sourceDir)
        val from = sha256(installed)
        val patches = release.optJSONArray("patches")
        val patch = (0 until (patches?.length() ?: 0)).map { patches!!.getJSONObject(it) }.firstOrNull { it.optString("from") == from }
        if (patch != null) {
            try {
                val diff = File(dir, "update.patch")
                get(patch.getString("url"), diff, patch.optLong("size")) { state.value = UpdateStatus.Downloading(version, it, patch = true) }
                if (sha256(diff) != patch.getString("sha256").lowercase()) throw IOException("patch checksum mismatch")
                BsPatch.apply(installed, diff, target)
                diff.delete()
                if (sha256(target) == want) return verifiedSignature(target)
                Log.w(TAG, "patched APK does not match; downloading the full APK")
            } catch (e: Exception) {
                Log.w(TAG, "patch failed; downloading the full APK", e)
            }
        }
        get(apk.getString("url"), target, apk.optLong("size")) { state.value = UpdateStatus.Downloading(version, it, patch = false) }
        if (sha256(target) != want) {
            target.delete()
            throw IOException("Download was corrupted; try again")
        }
        return verifiedSignature(target)
    }

    /** The update must be signed with the same key as this app. */
    private fun verifiedSignature(apk: File): File {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        val candidate = pm.getPackageArchiveInfo(apk.path, flags)
        val installed = pm.getPackageInfo(context.packageName, flags)
        if (candidate?.packageName != context.packageName || signatures(candidate) != signatures(installed)) {
            apk.delete()
            throw IOException("Update is not signed by Wantastic")
        }
        return apk
    }

    private fun signatures(info: PackageInfo): Set<String> {
        val sigs = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else @Suppress("DEPRECATION") info.signatures
        return sigs.orEmpty().map { hex(MessageDigest.getInstance("SHA-256").digest(it.toByteArray())) }.toSet()
    }

    private fun installQuietly(apk: File, version: String) {
        // Without confirmation only when Android allows it; otherwise a notification asks.
        if (Build.VERSION.SDK_INT >= 31 && installerIsUs()) commit(apk, version, foreground = false)
        else notifyReady(version)
    }

    private fun installerIsUs(): Boolean = runCatching {
        if (Build.VERSION.SDK_INT >= 30) context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName == context.packageName
        else false
    }.getOrDefault(false)

    private fun commit(apk: File, version: String, foreground: Boolean) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val id = installer.createSession(params)
        installer.openSession(id).use { session ->
            session.openWrite("wantastic.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
            val intent = Intent(context, InstallResultReceiver::class.java)
                .putExtra(EXTRA_VERSION, version)
                .putExtra(EXTRA_FOREGROUND, foreground)
            // Mutable: the installer adds the status and confirmation intent.
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
            session.commit(PendingIntent.getBroadcast(context, id, intent, flags).intentSender)
        }
    }

    private fun readyFile(): File? = dir.listFiles { f -> f.name.endsWith(".apk") }?.maxByOrNull { it.lastModified() }

    private fun cleanup(keep: File?) {
        dir.listFiles()?.forEach { if (it != keep) it.delete() }
    }

    private fun unmetered(): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        return !cm.isActiveNetworkMetered
    }

    private fun notifyReady(version: String) = notify(
        "Wantastic $version is ready", "Tap to install the update.",
        Intent(context, MainActivity::class.java).setAction(ACTION_INSTALL_UPDATE).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
    )

    internal fun notify(title: String, text: String, open: Intent) {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "Updates", NotificationManager.IMPORTANCE_DEFAULT).apply { setShowBadge(false) })
        }
        val pending = PendingIntent.getActivity(context, 1, open, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        runCatching {
            nm.notify(NOTIFY_ID, NotificationCompat.Builder(context, CHANNEL)
                .setSmallIcon(R.drawable.ic_tile).setContentTitle(title).setContentText(text)
                .setContentIntent(pending).setAutoCancel(true).build())
        }
    }

    internal fun installed(version: String) {
        state.value = UpdateStatus.UpToDate
        cleanup(keep = null)
        Log.i(TAG, "updated to $version")
    }

    internal fun failed(message: String) {
        state.value = UpdateStatus.Failed(message)
    }

    companion object {
        private const val TAG = "WantasticUpdate"
        private const val MANIFEST = "https://get.wantastic.app/android/latest/update.json"
        private const val CHANNEL = "updates"
        private const val NOTIFY_ID = 7101
        internal const val EXTRA_VERSION = "version"
        internal const val EXTRA_FOREGROUND = "foreground"

        /** The feed, or null when there is none (404). */
        private fun fetch(url: String): String? {
            val c = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000; readTimeout = 30_000; useCaches = false
                setRequestProperty("Cache-Control", "no-cache")
            }
            try {
                if (c.responseCode == 404) return null
                if (c.responseCode != 200) throw IOException("Update server answered ${c.responseCode}")
                return c.inputStream.bufferedReader().use { it.readText() }
            } finally {
                c.disconnect()
            }
        }

        private fun get(url: String, to: File, size: Long, progress: (Float) -> Unit) {
            require(url.startsWith("https://")) { "updates must come over HTTPS" }
            val c = (URL(url).openConnection() as HttpURLConnection).apply { connectTimeout = 15_000; readTimeout = 60_000 }
            try {
                if (c.responseCode != 200) throw IOException("Download failed (${c.responseCode})")
                val total = if (size > 0) size else c.contentLengthLong
                var done = 0L
                c.inputStream.use { input ->
                    to.outputStream().use { out ->
                        val buf = ByteArray(64 * 1024)
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            out.write(buf, 0, n)
                            done += n
                            if (total > 0) progress((done.toFloat() / total).coerceIn(0f, 1f))
                        }
                    }
                }
            } finally {
                c.disconnect()
            }
        }

        private fun sha256(f: File): String {
            val md = MessageDigest.getInstance("SHA-256")
            f.inputStream().use { input ->
                val buf = ByteArray(256 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    md.update(buf, 0, n)
                }
            }
            return hex(md.digest())
        }

        private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    }
}

/** Android reports the install here; it may first need the person's confirmation. */
class InstallResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val updates = Updates.get(context) as? StoreUpdates ?: return
        val version = intent.getStringExtra(StoreUpdates.EXTRA_VERSION).orEmpty()
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm = (if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                else intent.getParcelableExtra(Intent.EXTRA_INTENT)) ?: return
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                if (intent.getBooleanExtra(StoreUpdates.EXTRA_FOREGROUND, false)) context.startActivity(confirm)
                else updates.notify("Wantastic $version is ready", "Tap to install the update.", confirm)
            }
            PackageInstaller.STATUS_SUCCESS -> updates.installed(version)
            else -> updates.failed(intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "Install failed")
        }
    }
}
