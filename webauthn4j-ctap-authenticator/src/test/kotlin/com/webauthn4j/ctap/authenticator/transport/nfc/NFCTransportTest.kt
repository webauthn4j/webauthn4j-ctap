package com.webauthn4j.ctap.authenticator.transport.nfc

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCTransport
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.util.Base64UrlUtil
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

internal class NFCTransportTest {
    private val target = NFCTransport(CtapAuthenticator())

    @ExperimentalCoroutinesApi
    @Test
    fun processApduCommand_test() = runTest {
        val apdu = Base64UrlUtil.decode("gBAAAAEEAA")
        target.onCommandAPDUReceived(CommandAPDU.parse(apdu))
    }


}