package com.webauthn4j.ctap.authenticator.transport.nfc.apdu

import ch.qos.logback.core.encoder.ByteArrayUtil
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCTransport
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

internal class SelectCommandAPDUProcessorTest {
    private val target = NFCTransport(CtapAuthenticator()).selectCommandAPDUProcessor

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