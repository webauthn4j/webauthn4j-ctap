package com.webauthn4j.ctap.core.converter.jackson.serializer

import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.cbor.CBORMapper
import tools.jackson.module.kotlin.KotlinModule

import com.webauthn4j.converter.util.ObjectConverter
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
    private val cborMapper: CBORMapper

    init {
        val jsonMapper = JsonMapper()
        val ctapCborMapper = CBORMapper.builder()
            .addModule(CtapCBORModule())
            .addModule(KotlinModule.Builder().build())
            .build()
        cborMapper = ObjectConverter(jsonMapper, ctapCborMapper).cborMapper
    }

    @Test
    fun integer_keys_should_be_encoded_as_cbor_unsigned_integer() {
        val original = AuthenticatorGetInfoResponseData(
            listOf("FIDO_2_0"), null,
            CtapAuthenticator.AAGUID,
            null, null, null, null, null, null
        )
        val encoded = cborMapper.writeValueAsBytes(original)
        // CBOR unsigned integer key 0x01 (1) should appear, not CBOR text string "1" (0x6131)
        // A2 = 2-element map, 01 = unsigned integer 1 (versions key), 03 = unsigned integer 3 (aaguid key)
        Assertions.assertThat(encoded[0]).isEqualTo(0xA2.toByte()) // fixed-length map with 2 entries
        Assertions.assertThat(encoded[1]).isEqualTo(0x01.toByte()) // key 1 as CBOR unsigned integer
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
            2048u,
            listOf(PinProtocolVersion.VERSION_1),
            null,
            null,
            null
        )
        val encoded = cborMapper.writeValueAsBytes(original)
        val decoded = cborMapper.readValue(encoded, AuthenticatorGetInfoResponseData::class.java)
        Assertions.assertThat(decoded).isEqualTo(original)
    }

}
