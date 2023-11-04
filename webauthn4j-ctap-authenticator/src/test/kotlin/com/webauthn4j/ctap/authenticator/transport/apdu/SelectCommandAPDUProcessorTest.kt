package com.webauthn4j.ctap.authenticator.transport.apdu

import ch.qos.logback.core.encoder.ByteArrayUtil
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCConnector
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.mockito.Mockito

internal class SelectCommandAPDUProcessorTest {
    private val target = NFCConnector(
        Mockito.mock(TransactionManager::class.java),
        ObjectConverter()
    ).selectCommandAPDUProcessor

    @Disabled
    @Test
    fun isTarget_test() {
        val apdu = ByteArrayUtil.hexStringToByteArray("00A4040000A0000006472F0001")
        val commandAPDU = CommandAPDU.parse(apdu)
        Assertions.assertThat(target.isTarget(commandAPDU)).isTrue
    }

    @Disabled
    @ExperimentalCoroutinesApi
    @Test
    fun process_test() = runTest {
        val apdu = ByteArrayUtil.hexStringToByteArray("00A4040000A0000006472F0001")
        val commandAPDU = CommandAPDU.parse(apdu)
        target.process(commandAPDU)
    }
}