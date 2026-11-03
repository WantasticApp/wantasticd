package app.wantastic.android.account

import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceSetupLabelTest {
    private fun setup(claim: String) = DeviceSetups.Setup("t", "k", "p", claim)

    @Test fun networkIsThePrefixHoldingTheAddress() {
        val s = setup("""{"assigned_ip":"10.6.77.46/32","allowed_ips":["10.255.255.224/27","10.6.77.32/27","0.0.0.0/0"]}""")
        assertEquals("10.6.77.46", s.address)
        assertEquals("10.6.77.32/27", s.network)
    }

    @Test fun fallsBackToTheFirstPrefix() {
        assertEquals("10.6.84.192/27", setup("""{"allowed_ips":["0.0.0.0/0","10.6.84.192/27"]}""").network)
    }
}
