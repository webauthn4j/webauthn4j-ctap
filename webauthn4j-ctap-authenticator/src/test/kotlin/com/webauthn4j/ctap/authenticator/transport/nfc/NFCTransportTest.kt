package com.webauthn4j.ctap.authenticator.transport.nfc

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.util.Base64UrlUtil
import org.junit.jupiter.api.Test

internal class NFCTransportTest {
    private val target = NFCTransport(CtapAuthenticator())

    @Test
    suspend fun processApduCommand_test() {
        val apdu = Base64UrlUtil.decode("gBAAAAEEAA")
        target.onCommandAPDUReceived(CommandAPDU.parse(apdu))
    }


}