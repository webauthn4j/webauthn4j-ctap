package com.webauthn4j.ctap.core.converter.jackson.serializer

import tools.jackson.dataformat.cbor.CBORMapper
import tools.jackson.module.kotlin.KotlinModule
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionResponseData
import com.webauthn4j.ctap.core.util.internal.HexUtil
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class AuthenticatorGetAssertionResponseDataSerializerTest {
    @Test
    fun unsignedExtensionMapsUseDefiniteLengthsAndCanonicalKeyOrder() {
        val converter = CBORMapper.builder()
            .addModule(CtapCBORModule())
            .addModule(KotlinModule.Builder().build())
            .build()
        val response = AuthenticatorGetAssertionResponseData(
            null, byteArrayOf(1), byteArrayOf(2), null, null, null,
            mapOf("largeBlob" to linkedMapOf("originalSize" to 4, "blob" to byteArrayOf(3, 4)))
        )
        assertThat(converter.writeValueAsBytes(response)).isEqualTo(HexUtil.decode(
            "A302410103410208A1696C61726765426C6F62A264626C6F624203046C6F726967696E616C53697A6504"
        ))
    }
}
