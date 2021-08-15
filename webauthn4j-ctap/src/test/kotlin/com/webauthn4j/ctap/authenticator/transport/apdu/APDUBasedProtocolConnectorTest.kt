package com.webauthn4j.ctap.authenticator.transport.apdu

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.Base64UrlUtil
import com.webauthn4j.util.CertificateUtil
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Test
import org.mockito.Mockito

internal class APDUBasedProtocolConnectorTest {
    private val target =
        APDUBasedProtocolConnector(Mockito.mock(TransactionManager::class.java), ObjectConverter())

    @ExperimentalCoroutinesApi
    @Test
    fun processApduCommand_test() = runBlockingTest {
        val apdu = Base64UrlUtil.decode("gBAAAAEEAA")
        target.handleCommandAPDU(CommandAPDU.parse(apdu))
    }


}