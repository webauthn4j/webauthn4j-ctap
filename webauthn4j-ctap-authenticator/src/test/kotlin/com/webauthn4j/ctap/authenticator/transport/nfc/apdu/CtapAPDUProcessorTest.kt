package com.webauthn4j.ctap.authenticator.transport.nfc.apdu

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.UserVerificationHandler
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCTransport
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.util.Base64UrlUtil
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock

internal class CtapAPDUProcessorTest {
    private val target = NFCTransport(
        CtapAuthenticator(),
        mock(UserVerificationHandler::class.java)
    ).ctapAPDUProcessor

    @Disabled
    @Suppress("EXPERIMENTAL_API_USAGE")
    @Test
    fun processCtapFinalCommand_test() = runTest {
        val command = CommandAPDU.parse(Base64UrlUtil.decode("gBAAAAEEAA"))
        target.process(command)
    }
}