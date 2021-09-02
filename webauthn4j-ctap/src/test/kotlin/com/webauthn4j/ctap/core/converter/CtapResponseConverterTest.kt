package com.webauthn4j.ctap.core.converter

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.options.*
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.util.internal.HexUtil
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

internal class CtapResponseConverterTest {

    private val converter: CtapResponseConverter

    init {
        val jsonMapper = ObjectMapper()
        val cborMapper = ObjectMapper(CBORFactory())
        cborMapper.registerModule(CtapCBORModule())
        cborMapper.registerModule(KotlinModule())
        val objectConverter = ObjectConverter(jsonMapper, cborMapper)
        converter = CtapResponseConverter(objectConverter)
    }

    @Test
    fun convert_AuthenticatorGetInfoResponseData_test() {
        val responseData = AuthenticatorGetInfoResponseData(
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
        val original = AuthenticatorGetInfoResponse(CtapStatusCode.CTAP2_OK, responseData)
        val encoded = converter.convertToBytes(original)
        val decoded = converter.convert(encoded, AuthenticatorGetInfoResponse::class.java)
        Assertions.assertThat(encoded.first()).isEqualTo(CtapStatusCode.CTAP2_OK.byte)
        Assertions.assertThat(decoded).isEqualTo(original)
    }

    @Test
    fun convertToBytes_test() {
        val response = AuthenticatorMakeCredentialResponse(CtapStatusCode.CTAP2_ERR_PIN_NOT_SET)
        val bytes = converter.convertToBytes(response)
        Assertions.assertThat(bytes).isEqualTo(HexUtil.decode("35"))
    }

}