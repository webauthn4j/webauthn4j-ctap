package com.webauthn4j.ctap.authenticator.transport.apdu

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCConnector
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.util.Base64UrlUtil
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

internal class CtapAPDUProcessorTest {
    private val objectConverter = ObjectConverter()
    private val transactionManager: TransactionManager = object : TransactionManager() {}
    private val target = NFCConnector(
        transactionManager,
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