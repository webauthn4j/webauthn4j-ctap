package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.Connection
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.data.PinProtocolVersion
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.PlatformOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.UserPresenceOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class AuthenticatorGetInfoResponseDataSerializerTest {
    private val converter: CborConverter

    init {
        val jsonMapper = ObjectMapper()
        val cborMapper = ObjectMapper(CBORFactory())
        cborMapper.registerModule(CtapCBORModule())
        cborMapper.registerModule(KotlinModule.Builder().build())
        converter = ObjectConverter(jsonMapper, cborMapper).cborConverter
    }

    @Test
    fun test() {
        val original = AuthenticatorGetInfoResponseData(
            listOf("FIDO_2_0"), emptyList(),
            CtapAuthenticator.AAGUID,
            AuthenticatorGetInfoResponseData.Options(
                PlatformOption.CROSS_PLATFORM,
                ResidentKeyOption.SUPPORTED,
                ClientPINOption.NOT_SET,
                UserPresenceOption.SUPPORTED,
                UserVerificationOption.READY
            ),
            2048u, listOf(PinProtocolVersion.VERSION_1)
        )
        val encoded = converter.writeValueAsBytes(original)
        val decoded = converter.readValue(encoded, AuthenticatorGetInfoResponseData::class.java)
        Assertions.assertThat(decoded).isEqualTo(original)
    }

}
