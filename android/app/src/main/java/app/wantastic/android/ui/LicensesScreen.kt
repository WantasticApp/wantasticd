package app.wantastic.android.ui

import android.content.Context
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mikepenz.aboutlibraries.Libs
import com.mikepenz.aboutlibraries.util.withContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray

/** One open-source component shipped in the app, with its license text. */
data class Notice(val name: String, val version: String, val license: String, val text: String)

/** Everything in the app: Kotlin/Java libraries (built at compile time) and the Go engine's modules. */
private fun loadNotices(context: Context): List<Notice> {
    val libs = Libs.Builder().withContext(context).build().libraries.map { lib ->
        Notice(
            name = lib.name.ifBlank { lib.uniqueId },
            version = lib.artifactVersion.orEmpty(),
            license = lib.licenses.joinToString { it.spdxId ?: it.name },
            text = lib.licenses.mapNotNull { it.licenseContent ?: it.url }.joinToString("\n\n"),
        )
    }
    val go = runCatching {
        val arr = JSONArray(context.assets.open("go-licenses.json").bufferedReader().use { it.readText() })
        (0 until arr.length()).map { arr.getJSONObject(it) }.map {
            Notice(it.getString("path"), it.optString("version"), "Go engine", it.getString("license"))
        }
    }.getOrDefault(emptyList())
    return (libs + go).sortedBy { it.name.lowercase() }
}

@Composable
fun LicensesScreen() {
    val context = LocalContext.current
    val notices by produceState<List<Notice>?>(null) { value = withContext(Dispatchers.IO) { loadNotices(context) } }
    Column(Modifier.fillMaxSize()) {
        GlassTitle("Open-source licenses", notices?.let { "${it.size} components make Wantastic" })
        LazyColumn(
            contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 4.dp, bottom = 110.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(notices.orEmpty(), key = { it.name + it.version }) { n -> NoticeCard(n) }
        }
    }
}

@Composable
private fun NoticeCard(n: Notice) {
    var open by remember { mutableStateOf(false) }
    GlassCard(Modifier.fillMaxWidth().animateContentSize(), onClick = { open = !open }) {
        Text(n.name, color = Glass.Text, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
        Text(listOf(n.version, n.license).filter { it.isNotBlank() }.joinToString(" · "), color = Glass.TextDim, fontSize = 12.sp)
        if (open && n.text.isNotBlank()) {
            Text(
                n.text, color = Glass.TextDim, fontSize = 11.sp, fontFamily = FontFamily.Monospace, lineHeight = 15.sp,
                modifier = Modifier.padding(top = 10.dp).clickable(enabled = false) {},
            )
        }
    }
}
