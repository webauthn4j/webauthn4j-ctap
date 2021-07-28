package com.unifidokey.driver.persistence.dao

import android.security.keystore.KeyProperties
import com.google.common.truth.Truth
import com.webauthn4j.data.SignatureAlgorithm
import org.junit.Before
import org.junit.Test
import java.util.*

class AndroidKeyStoreDaoTest {

    private lateinit var target: AndroidKeyStoreDao

    @Before
    fun setup() {
        target = AndroidKeyStoreDao()
    }

    @Test
    fun findOrCreateEncryptionKey_test() {
        val secretKey = target.findOrCreateEncryptionKey()
        Truth.assertThat(secretKey).isNotNull()
    }

    @Test
    fun findOrCreateEncryptionKey_will_return_same_value() {
        Truth.assertThat(target.findOrCreateEncryptionKey())
            .isEqualTo(target.findOrCreateEncryptionKey())
    }

    @Test
    fun createCredentialKeyPair_ES256_test() {
        val alias = UUID.randomUUID().toString()
        val keyPair = target.createCredentialKeyPair(alias, SignatureAlgorithm.ES256, ByteArray(32))
        Truth.assertThat(keyPair).isNotNull()
        Truth.assertThat(keyPair.public.algorithm).isEqualTo(KeyProperties.KEY_ALGORITHM_EC)
        Truth.assertThat(keyPair.private.algorithm).isEqualTo(KeyProperties.KEY_ALGORITHM_EC)
        val attestationCertificatePath = target.findCredentialAttestationCertificatePath(alias)
        val attestationChallengeExtension =
            attestationCertificatePath!!.endEntityAttestationCertificate.certificate.getExtensionValue(
                "1.3.6.1.4.1.11129.2.1.17"
            )
        Truth.assertThat(attestationChallengeExtension).isNotNull()
    }

    @Test
    fun createCredentialKeyPair_RS1_test() {
        val alias = UUID.randomUUID().toString()
        val keyPair = target.createCredentialKeyPair(alias, SignatureAlgorithm.RS1, ByteArray(32))
        Truth.assertThat(keyPair).isNotNull()
        Truth.assertThat(keyPair.public.algorithm).isEqualTo(KeyProperties.KEY_ALGORITHM_RSA)
        Truth.assertThat(keyPair.private.algorithm).isEqualTo(KeyProperties.KEY_ALGORITHM_RSA)
        val attestationCertificatePath = target.findCredentialAttestationCertificatePath(alias)
        val attestationChallengeExtension =
            attestationCertificatePath!!.endEntityAttestationCertificate.certificate.getExtensionValue(
                "1.3.6.1.4.1.11129.2.1.17"
            )
        Truth.assertThat(attestationChallengeExtension).isNotNull()
    }

    @Test
    fun createCredentialKeyPair_with_attestationChallenge_test() {
        val alias = UUID.randomUUID().toString()
        val attestationChallenge = ByteArray(32)
        val keyPair =
            target.createCredentialKeyPair(alias, SignatureAlgorithm.ES256, attestationChallenge)
        Truth.assertThat(keyPair).isNotNull()
        val attestationCertificatePath = target.findCredentialAttestationCertificatePath(alias)
        val attestationChallengeExtension =
            attestationCertificatePath!!.endEntityAttestationCertificate.certificate.getExtensionValue(
                "1.3.6.1.4.1.11129.2.1.17"
            )
        Truth.assertThat(attestationChallengeExtension).isNotNull()
    }

    @Test
    fun findCredentialKeyPair_test() {
        val alias = UUID.randomUUID().toString()
        val original =
            target.createCredentialKeyPair(alias, SignatureAlgorithm.ES256, ByteArray(32))
        val retrieved = target.findCredentialKeyPair(alias)
        Truth.assertThat(original.public).isEqualTo(retrieved!!.public)
        Truth.assertThat(original.private).isEqualTo(retrieved.private)
    }

    @Test
    fun findOrCreateDeviceAttestationPrivateKey_test() {
        val privateKey = target.findOrCreateDeviceAttestationPrivateKey()
        Truth.assertThat(privateKey).isNotNull()
        Truth.assertThat(privateKey).isEqualTo(target.findOrCreateDeviceAttestationPrivateKey())
    }

    @Test
    fun findOrCreateDeviceAttestationCertificate_test() {
        val attestationCertificatePath = target.findOrCreateDeviceAttestationCertificatePath()
        Truth.assertThat(attestationCertificatePath).isNotNull()
        Truth.assertThat(attestationCertificatePath)
            .isEqualTo(target.findOrCreateDeviceAttestationCertificatePath())
    }
}