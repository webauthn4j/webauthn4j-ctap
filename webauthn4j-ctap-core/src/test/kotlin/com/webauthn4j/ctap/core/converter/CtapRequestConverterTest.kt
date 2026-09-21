package com.webauthn4j.ctap.core.converter

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINRequest
import com.webauthn4j.ctap.core.data.PinSubCommand
import com.webauthn4j.ctap.core.util.internal.HexUtil
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.cbor.CBORMapper
import tools.jackson.module.kotlin.KotlinModule

internal class CtapRequestConverterTest {

    private val converter = CtapRequestConverter(
        ObjectConverter(
            JsonMapper(),
            CBORMapper.builder()
                .addModule(CtapCBORModule())
                .addModule(KotlinModule.Builder().build())
                .build()
        )
    )

    @Test
    fun `ClientPIN getPinRetries accepts an omitted pinUvAuthProtocol`() {
        val request = converter.convert(requireNotNull(HexUtil.decode("06a10201")))

        assertThat(request).isInstanceOf(AuthenticatorClientPINRequest::class.java)
        request as AuthenticatorClientPINRequest
        assertThat(request.subCommand).isEqualTo(PinSubCommand.GET_PIN_RETRIES)
        assertThat(request.pinProtocol).isNull()
    }
}
