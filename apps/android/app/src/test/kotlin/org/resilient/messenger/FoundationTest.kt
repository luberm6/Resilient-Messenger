package org.resilient.messenger

import org.junit.Assert.assertEquals
import org.junit.Test

class FoundationTest {
    @Test fun packageIdentityIsStable() { assertEquals("org.resilient.messenger", BuildConfig.APPLICATION_ID) }
}
