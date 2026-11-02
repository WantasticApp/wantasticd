package app.wantastic.android.update

import android.app.Activity
import android.content.Context
import android.util.Log
import app.wantastic.android.settings.AppSettings
import com.google.android.play.core.appupdate.AppUpdateManagerFactory
import com.google.android.play.core.appupdate.AppUpdateOptions
import com.google.android.play.core.install.InstallStateUpdatedListener
import com.google.android.play.core.install.model.AppUpdateType
import com.google.android.play.core.install.model.InstallStatus
import com.google.android.play.core.install.model.UpdateAvailability
import com.google.android.play.core.ktx.requestAppUpdateInfo
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The Play build updates through Google Play's in-app updates: Play
 * downloads only what changed, in the background, and Wantastic asks to
 * restart once it is ready. Play also updates the app on its own schedule.
 */
class StoreUpdates(private val context: Context) : Updater {
    private val manager = AppUpdateManagerFactory.create(context)
    private val settings = AppSettings.get(context)
    private val state = MutableStateFlow<UpdateStatus>(UpdateStatus.Idle)
    override val status: StateFlow<UpdateStatus> = state.asStateFlow()
    override val selfUpdating = false
    private var available: String? = null

    private val listener = InstallStateUpdatedListener { s ->
        val version = available ?: "update"
        state.value = when (s.installStatus()) {
            InstallStatus.DOWNLOADING -> UpdateStatus.Downloading(
                version, if (s.totalBytesToDownload() > 0) s.bytesDownloaded().toFloat() / s.totalBytesToDownload() else 0f, patch = true,
            )
            InstallStatus.DOWNLOADED -> UpdateStatus.Ready(version)
            InstallStatus.INSTALLING -> UpdateStatus.Installing
            InstallStatus.INSTALLED -> UpdateStatus.UpToDate
            InstallStatus.FAILED -> UpdateStatus.Failed("Google Play could not update Wantastic")
            else -> state.value
        }
    }

    init {
        manager.registerListener(listener)
    }

    override suspend fun check(interactive: Boolean) {
        state.value = UpdateStatus.Checking
        try {
            val info = manager.requestAppUpdateInfo()
            settings.lastUpdateCheck = System.currentTimeMillis()
            state.value = when {
                info.installStatus() == InstallStatus.DOWNLOADED -> UpdateStatus.Ready(available ?: "update")
                info.updateAvailability() == UpdateAvailability.UPDATE_AVAILABLE -> {
                    available = info.availableVersionCode().toString()
                    UpdateStatus.Available("build ${info.availableVersionCode()}")
                }
                else -> UpdateStatus.UpToDate
            }
        } catch (e: Exception) {
            // Not installed from Play (a test build) or Play unavailable.
            Log.w("WantasticUpdate", "Play update check failed", e)
            state.value = UpdateStatus.Failed("Updates come from Google Play")
        }
    }

    override fun install(activity: Activity) {
        when (state.value) {
            is UpdateStatus.Ready -> manager.completeUpdate()
            is UpdateStatus.Available -> manager.appUpdateInfo.addOnSuccessListener { info ->
                if (info.isUpdateTypeAllowed(AppUpdateType.FLEXIBLE)) {
                    manager.startUpdateFlow(info, activity, AppUpdateOptions.newBuilder(AppUpdateType.FLEXIBLE).build())
                }
            }
            else -> Unit
        }
    }
}
