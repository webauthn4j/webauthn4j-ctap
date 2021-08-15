package com.webauthn4j.ctap.authenticator.store

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.webauthn4j.converter.util.CborConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.core.converter.jackson.PublicKeyCredentialSourceCBORModule
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.util.ECUtil
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Instant

internal class NonResidentUserCredentialTest {

    private lateinit var cborConverter: CborConverter

    @BeforeEach
    fun setup() {
        val jsonMapper = ObjectMapper()
        val cborMapper = ObjectMapper(CBORFactory())
        cborMapper.registerModule(JavaTimeModule())
        cborMapper.registerModule(PublicKeyCredentialSourceCBORModule())
        cborConverter = ObjectConverter(jsonMapper, cborMapper).cborConverter
    }

    @Test
    fun serialize_test() {
        val target = createNonResidentUserCredential()
        cborConverter.writeValueAsBytes(target)
    }

    @Test
    fun deserialize_test() {
        val target = createNonResidentUserCredential()
        val bytes = cborConverter.writeValueAsBytes(target)
        val data = cborConverter.readValue(
            bytes,
            object : TypeReference<NonResidentUserCredential>() {})
        assertThat(data).isEqualTo(target)
    }

    private fun createNonResidentUserCredential(): NonResidentUserCredential {
        val credentialId = ByteArray(32)
        val userCredentialKey =
            NonResidentCredentialKey(SignatureAlgorithm.ES256, ECUtil.createKeyPair())
        val userHandle = ByteArray(32)
        return NonResidentUserCredential(
            credentialId,
            userCredentialKey,
            userHandle,
            "username",
            "displayName",
            "rpId",
            "rpName",
            Instant.now(),
            null,
            emptyMap()
        )
    }
}