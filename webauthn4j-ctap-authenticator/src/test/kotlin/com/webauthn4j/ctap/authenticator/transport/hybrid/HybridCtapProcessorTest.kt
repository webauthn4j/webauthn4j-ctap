package com.webauthn4j.ctap.authenticator.transport.hybrid

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.core.data.CtapStatusCode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class HybridCtapProcessorTest {
    @Test
    suspend fun `GetInfo crosses the Hybrid CTAP processor`() {
        val authenticator = CtapAuthenticator()
        val response = HybridCtapProcessor(authenticator.createSession()).process(byteArrayOf(0x04))

        assertEquals(CtapStatusCode.CTAP1_ERR_SUCCESS.byte, response.first())
        assert(response.size > 1)
    }

    @Test
    suspend fun `invalid CTAP command returns an error status`() {
        val response = HybridCtapProcessor(CtapAuthenticator().createSession()).process(byteArrayOf(0x7f))

        assertEquals(CtapStatusCode.CTAP1_ERR_OTHER.byte, response.single())
    }
}
