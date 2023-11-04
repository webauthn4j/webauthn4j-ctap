package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.PlatformOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.UserPresenceOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.ctap.core.util.internal.HexUtil
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class AuthenticatorGetInfoResponseDataOptionsSerializerTest {
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
        val original = AuthenticatorGetInfoResponseData.Options(
            PlatformOption.CROSS_PLATFORM,
            ResidentKeyOption.SUPPORTED,
            ClientPINOption.NOT_SET,
            UserPresenceOption.SUPPORTED,
            UserVerificationOption.NOT_SUPPORTED
        )
        val encoded = converter.writeValueAsBytes(original)
        Assertions.assertThat(encoded)
            .isEqualTo(HexUtil.decode("A462726BF5627570F564706C6174F469636C69656E7450696EF4"))
        val decoded =
            converter.readValue(encoded, AuthenticatorGetInfoResponseData.Options::class.java)
        Assertions.assertThat(decoded).isEqualTo(original)
    }

}
