package com.webauthn4j.ctap.core.data.nfc

import ch.qos.logback.core.encoder.ByteArrayUtil
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU.Companion.parse
import com.webauthn4j.util.Base64UrlUtil
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class CommandAPDUTest {
    @Test
    fun parse_select_APDU() {
        val apdu = ByteArrayUtil.hexStringToByteArray("00A4040008A0000006472F000100")
        val command = parse(apdu)
        Assertions.assertThat(command.cla).isEqualTo(0x00.toByte())
        Assertions.assertThat(command.ins).isEqualTo(0xA4.toByte())
        Assertions.assertThat(command.p1).isEqualTo(0x04.toByte())
        Assertions.assertThat(command.p2).isEqualTo(0x00.toByte())
        Assertions.assertThat(command.lc).isEqualTo(byteArrayOf(0x08.toByte()))
        Assertions.assertThat(command.dataIn)
            .isEqualTo(ByteArrayUtil.hexStringToByteArray("A0000006472F0001"))
        Assertions.assertThat(command.le).isEqualTo(byteArrayOf(0x00.toByte()))
    }

    @Test
    fun parse_test2() {
        val apdu = Base64UrlUtil.decode("gBAAAAEEAA")
        val command = parse(apdu)
        Assertions.assertThat(command).isNotNull
    }

    @Test
    fun parse_unknown_shortAPDU() {
        val apdu = ByteArrayUtil.hexStringToByteArray("8012010000")
        val command = parse(apdu)
        Assertions.assertThat(command.cla).isEqualTo(0x80.toByte())
        Assertions.assertThat(command.ins).isEqualTo(0x12.toByte())
        Assertions.assertThat(command.p1).isEqualTo(0x01.toByte())
        Assertions.assertThat(command.p2).isEqualTo(0x00.toByte())
        Assertions.assertThat(command.lc).isEqualTo(null)
        Assertions.assertThat(command.dataIn).isEqualTo(null)
        Assertions.assertThat(command.le).isEqualTo(byteArrayOf(0x00.toByte()))
    }
}