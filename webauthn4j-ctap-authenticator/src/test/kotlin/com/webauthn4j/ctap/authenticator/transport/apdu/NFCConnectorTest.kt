package com.webauthn4j.ctap.authenticator.transport.apdu

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCConnector
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.util.Base64UrlUtil
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.mockito.Mockito

internal class NFCConnectorTest {
    private val target =
        NFCConnector(Mockito.mock(TransactionManager::class.java), ObjectConverter())

    @ExperimentalCoroutinesApi
    @Test
    fun processApduCommand_test() = runTest {
        val apdu = Base64UrlUtil.decode("gBAAAAEEAA")
        target.handleCommandAPDU(CommandAPDU.parse(apdu))
    }


}