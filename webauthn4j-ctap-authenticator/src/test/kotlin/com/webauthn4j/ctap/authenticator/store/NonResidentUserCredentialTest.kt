package com.webauthn4j.ctap.authenticator.store

import tools.jackson.core.type.TypeReference
import tools.jackson.dataformat.cbor.CBORMapper

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.data.credential.NonResidentCredentialKey
import com.webauthn4j.ctap.authenticator.data.credential.NonResidentUserCredential
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ECUtil
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Instant

internal class NonResidentUserCredentialTest {

    private val cborMapper: CBORMapper = CtapAuthenticator().objectConverter.cborMapper

    @Test
    fun serialize_test() {
        val target = createNonResidentUserCredential()
        cborMapper.writeValueAsBytes(target)
    }

    @Test
    fun deserialize_test() {
        val target = createNonResidentUserCredential()
        val bytes = cborMapper.writeValueAsBytes(target)
        val data = cborMapper.readValue(
            bytes,
            object : TypeReference<NonResidentUserCredential>() {})
        assertThat(data).isEqualTo(target)
    }

    private fun createNonResidentUserCredential(): NonResidentUserCredential {
        val credentialId = ByteArray(32)
        val userCredentialKey =
            NonResidentCredentialKey.create(COSEAlgorithmIdentifier.ES256, ECUtil.createKeyPair())
        val userHandle = ByteArray(32)
        return NonResidentUserCredential(
            credentialId,
            userCredentialKey,
            userHandle,
            "username",
            "displayName",
            "icon",
            "rpId",
            "rpName",
            "rpIcon",
            Instant.now(),
            null,
            emptyMap()
        )
    }
}
