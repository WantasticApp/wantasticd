package app.wantastic.android.claim

import org.junit.Assert.assertEquals
import org.junit.Test

class ClaimLinkTest {
    private val key = "bTJmHCbkxYq3Xg8x+S5Rr0b5pGGqP2V7ZcPmLe4/2Ac="

    @Test
    fun matchesTheDesktopAgentsClaimLink() {
        assertEquals(
            "https://console.wantastic.app/#desktop?claim_public_key=bTJmHCbkxYq3Xg8x%2BS5Rr0b5pGGqP2V7ZcPmLe4%2F2Ac%3D" +
                "&wantastic_server=https%3A%2F%2Fconsole.wantastic.app&hostname=Kimo%27s+Pixel+8",
            ClaimLink.build(null, key, "Kimo's Pixel 8"),
        )
    }

    @Test
    fun normalizesTheServer() {
        assertEquals("https://console.example.net", ClaimLink.normalizeServer("console.example.net/"))
        assertEquals("https://console.example.net", ClaimLink.normalizeServer("https://console.example.net/path?x=1"))
        assertEquals(ClaimLink.DEFAULT_SERVER, ClaimLink.normalizeServer("  "))
    }

    @Test
    fun dropsMeaninglessHostnames() {
        assertEquals("", ClaimLink.cleanHostname("localhost"))
        assertEquals("", ClaimLink.cleanHostname("Android"))
        assertEquals("office-tab", ClaimLink.cleanHostname("office-tab.lan"))
        assertEquals(64, ClaimLink.cleanHostname("x".repeat(80)).length)
    }

    @Test
    fun omitsAnEmptyHostname() {
        assertEquals(
            "https://console.wantastic.app/#desktop?claim_public_key=abc&wantastic_server=https%3A%2F%2Fconsole.wantastic.app",
            ClaimLink.build("", "abc", "localhost"),
        )
    }
}
