package app.wantastic.android.update

import android.app.Activity
import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import app.wantastic.android.BuildConfig
import app.wantastic.android.settings.AppSettings
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.TimeUnit

/** Where an update stands; the Settings screen shows exactly this. */
sealed interface UpdateStatus {
    data object Idle : UpdateStatus
    data object Checking : UpdateStatus
    data object UpToDate : UpdateStatus
    data class Available(val version: String) : UpdateStatus
    /** [patch]: only the difference is downloading, not the whole app. */
    data class Downloading(val version: String, val fraction: Float, val patch: Boolean) : UpdateStatus
    data class Ready(val version: String) : UpdateStatus
    data object Installing : UpdateStatus
    data class Failed(val message: String) : UpdateStatus
}

/**
 * Updates for this build. The Play build updates through Google Play (Play
 * policy allows no other way); the direct build updates itself from
 * get.wantastic.app with binary patches. Each flavor provides [StoreUpdates].
 */
interface Updater {
    val status: StateFlow<UpdateStatus>
    /** True when this build downloads and installs its own updates. */
    val selfUpdating: Boolean
    /** [interactive]: the person asked, so download now even on mobile data. */
    suspend fun check(interactive: Boolean)
    /** Installs a downloaded update; may show Android's confirmation. */
    fun install(activity: Activity)
}

object Updates {
    @Volatile
    private var updater: Updater? = null

    fun get(context: Context): Updater = updater ?: synchronized(this) {
        updater ?: StoreUpdates(context.applicationContext).also { updater = it }
    }

    /**
     * Keeps the background check scheduled to match the settings: twice a
     * day, on Wi-Fi when asked. Only the direct build checks in the
     * background; Google Play updates the Play build itself.
     */
    fun schedule(context: Context) {
        val work = WorkManager.getInstance(context)
        val settings = AppSettings.get(context)
        if (!BuildConfig.SELF_UPDATE || !settings.autoUpdate.value) {
            work.cancelUniqueWork(WORK)
            return
        }
        val request = PeriodicWorkRequestBuilder<UpdateWorker>(12, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(if (settings.wifiOnly.value) NetworkType.UNMETERED else NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true)
                    .build(),
            )
            .build()
        work.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.UPDATE, request)
    }

    private const val WORK = "wantastic-update"
}

class UpdateWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        Updates.get(applicationContext).check(interactive = false)
        return Result.success()
    }
}
