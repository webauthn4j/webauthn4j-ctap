package com.webauthn4j.ctap.authenticator.transport.apdu

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.Connection
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCConnector
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.util.Base64UrlUtil
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

internal class CtapAPDUProcessorTest {
    private val objectConverter = ObjectConverter()
    private val ctapAuthenticator = CtapAuthenticator()
    private val target = NFCConnector(
        ctapAuthenticator,
        objectConverter
    ).ctapAPDUProcessor

    @Disabled
    @Suppress("EXPERIMENTAL_API_USAGE")
    @Test
    fun processCtapFinalCommand_test() = runTest {
        val command = CommandAPDU.parse(Base64UrlUtil.decode("gBAAAAEEAA"))
        target.process(command)
    }
}