package app.wantastic.android.account

import app.wantastic.android.ui.unixCommand
import app.wantastic.android.ui.windowsCommand
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OnboardingKeyTest {
    @Test fun parsesProtoJson() {
        val k = OnboardingKey.from(
            JSONObject("""{"id":"k1","name":"Added from Pixel","token":"tok","max_uses":1,"usage_count":0,
                "expires_at":"2099-01-02T03:04:05Z","created_at":{"seconds":1700000000,"nanos":5000000}}"""),
        )
        assertEquals(1, k.remaining)
        assertEquals(java.time.Instant.parse("2099-01-02T03:04:05Z").toEpochMilli(), k.expiresAtMs)
        assertEquals(1_700_000_000_005L, k.createdAtMs)
        assertTrue(k.usable())
    }

    @Test fun zeroTimeNeverExpiresAndUnlimited() {
        val k = OnboardingKey.from(JSONObject("""{"token":"t","expires_at":"0001-01-01T00:00:00Z"}"""))
        assertEquals(0L, k.expiresAtMs)
        assertNull(k.remaining)
        assertTrue(k.usable())
    }

    @Test fun usedUpOrExpiredIsNotUsable() {
        assertFalse(OnboardingKey.from(JSONObject("""{"token":"t","max_uses":2,"usage_count":2}""")).usable())
        assertFalse(OnboardingKey.from(JSONObject("""{"token":"t","expires_at":"2001-01-01T00:00:00Z"}""")).usable())
        assertFalse(OnboardingKey.from(JSONObject("""{"token":""}""")).usable())
    }

    // Same text as the console's buildUnixSetupCommand / buildWindowsSetupCommand.
    @Test fun commandsMatchTheConsole() {
        assertEquals("curl -fsSL https://get.wantastic.app/install.sh | sudo sh -s -- --login --token 'a'\\''b'", unixCommand("a'b"))
        assertEquals(
            "\$installer = Join-Path \$env:TEMP 'wantastic-install.ps1'\n" +
                "Invoke-WebRequest -Uri 'https://get.wantastic.app/install.ps1' -OutFile \$installer\n" +
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \$installer -Token 'a''b'",
            windowsCommand("a'b"),
        )
    }
}
