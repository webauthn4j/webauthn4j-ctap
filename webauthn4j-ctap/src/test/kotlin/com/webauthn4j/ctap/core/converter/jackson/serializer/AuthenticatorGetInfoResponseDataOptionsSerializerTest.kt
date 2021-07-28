package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.options.*
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.util.internal.HexUtil
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class AuthenticatorGetInfoResponseDataOptionsSerializerTest {
    private val converter: CborConverter

    init {
        val jsonMapper = ObjectMapper()
        val cborMapper = ObjectMapper(CBORFactory())
        cborMapper.registerModule(CtapCBORModule())
        converter = ObjectConverter(jsonMapper, cborMapper).cborConverter
    }

    @Test
    fun test() {
        val original = AuthenticatorGetInfoResponseData.Options(
            PlatformOption.CROSS_PLATFORM,
            ResidentKeyOption.SUPPORTED,
            ClientPINOption.NOT_SET,
            UserPresenceOption.SUPPORTED,
            UserVerificationOption.NOT_SUPPORTED
        )
        val encoded = converter.writeValueAsBytes(original)
        Assertions.assertThat(encoded)
            .isEqualTo(HexUtil.decode("A464706C6174F462726BF569636C69656E7450696EF4627570F5"))
        val decoded =
            converter.readValue(encoded, AuthenticatorGetInfoResponseData.Options::class.java)
        Assertions.assertThat(decoded).isEqualTo(original)
    }

}
