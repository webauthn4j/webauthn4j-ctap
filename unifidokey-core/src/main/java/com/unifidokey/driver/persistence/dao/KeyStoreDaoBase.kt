package com.unifidokey.driver.persistence.dao

import android.security.keystore.KeyProperties
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.SignatureAlgorithm.*
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.security.*
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.util.*
import java.util.stream.Collectors
import javax.crypto.SecretKey

abstract class KeyStoreDaoBase protected constructor(
    protected val keyStore: KeyStore,
    protected val password: String?
) : KeyStoreDao {

    override fun findOrCreateEncryptionKey(): SecretKey {
        createEncryptionKeyIfNotExists()
        return try {
            val passwordCharArray = password?.toCharArray()
            val protectionParameter: KeyStore.ProtectionParameter =
                KeyStore.PasswordProtection(passwordCharArray)
            val entry = keyStore.getEntry(
                CREDENTIAL_SOURCE_ENCRYPTION_KEY_ENTRY,
                protectionParameter
            ) as KeyStore.SecretKeyEntry
            entry.secretKey
        } catch (e: KeyStoreException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: UnrecoverableEntryException) {
            throw UnexpectedCheckedException(e)
        }
    }

    override fun createCredentialKeyPair(
        alias: String,
        alg: SignatureAlgorithm,
        attestationChallenge: ByteArray?
    ): KeyPair {
        createKeyPair(alias, alg, attestationChallenge)
        return findKeyPair(alias)!!
    }

    override fun findCredentialKeyPair(alias: String): KeyPair? {
        return findKeyPair(alias)
    }

    override fun findCredentialAttestationCertificatePath(alias: String): AttestationCertificatePath? {
        return findAttestationCertificatePath(alias)
    }

    override fun findOrCreateDeviceAttestationPrivateKey(): PrivateKey {
        return findOrCreateKeyPair(ATTESTATION_KEY_ENTRY, SignatureAlgorithm.ES256, null).private
    }

    override fun findOrCreateIssuerPrivateKey(): PrivateKey {
        return findOrCreateKeyPair(ISSUER_KEY_ENTRY, SignatureAlgorithm.ES256, null).private
    }

    override fun findOrCreateDeviceAttestationCertificatePath(): AttestationCertificatePath {
        return findOrCreateAttestationCertificatePath(
            ATTESTATION_KEY_ENTRY,
            SignatureAlgorithm.ES256,
            null
        )
    }

    override fun deleteAll() {
        try {
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                keyStore.deleteEntry(alias)
            }
        } catch (e: KeyStoreException) {
            throw UnexpectedCheckedException(e)
        }
    }

    override fun delete(alias: String?) {
        try {
            keyStore.deleteEntry(alias)
        } catch (e: KeyStoreException) {
            throw UnexpectedCheckedException(e)
        }
    }

    private fun findOrCreateKeyPair(
        alias: String,
        alg: SignatureAlgorithm,
        attestationChallenge: ByteArray?
    ): KeyPair {
        createKeyPairIfNotExists(alias, alg, attestationChallenge)
        return findKeyPair(alias)!!
    }

    private fun findOrCreateAttestationCertificatePath(
        alias: String,
        alg: SignatureAlgorithm,
        attestationChallenge: ByteArray?
    ): AttestationCertificatePath {
        createKeyPairIfNotExists(alias, alg, attestationChallenge)
        return findAttestationCertificatePath(alias)!!
    }

    private fun findKeyPair(alias: String): KeyPair? {
        return try {
            val passwordCharArray = password?.toCharArray()
            val protectionParameter: KeyStore.ProtectionParameter =
                KeyStore.PasswordProtection(passwordCharArray)
            val entry = keyStore.getEntry(alias, protectionParameter) as KeyStore.PrivateKeyEntry
            val publicKey = entry.certificate.publicKey
            val privateKey = entry.privateKey
            KeyPair(publicKey, privateKey)
        } catch (e: KeyStoreException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: UnrecoverableEntryException) {
            throw UnexpectedCheckedException(e)
        }
    }

    private fun findAttestationCertificatePath(alias: String): AttestationCertificatePath? {
        return try {
            val certificates = keyStore.getCertificateChain(alias)
            AttestationCertificatePath(
                Arrays.stream(certificates).map { item: Certificate? -> item as X509Certificate? }
                    .collect(Collectors.toList())
            )
        } catch (e: KeyStoreException) {
            throw UnexpectedCheckedException(e)
        }
    }

    private fun createEncryptionKeyIfNotExists() {
        if (containsAlias(CREDENTIAL_SOURCE_ENCRYPTION_KEY_ENTRY)) {
            return
        }
        createSecretKey(CREDENTIAL_SOURCE_ENCRYPTION_KEY_ENTRY)
    }

    private fun createKeyPairIfNotExists(
        alias: String,
        alg: SignatureAlgorithm,
        attestationChallenge: ByteArray?
    ) {
        if (containsAlias(alias)) {
            return
        }
        createKeyPair(alias, alg, attestationChallenge)
    }

    protected fun createKeyPair(
        alias: String,
        alg: SignatureAlgorithm,
        attestationChallenge: ByteArray?
    ) {
        when {
            alg == ES256 -> createKeyPair(
                alias,
                KeyProperties.KEY_ALGORITHM_EC,
                ECGenParameterSpec("secp256r1"),
                alg,
                attestationChallenge
            )
            alg == ES384 -> createKeyPair(
                alias,
                KeyProperties.KEY_ALGORITHM_EC,
                ECGenParameterSpec("secp384r1"),
                alg,
                attestationChallenge
            )
            alg == ES512 -> createKeyPair(
                alias,
                KeyProperties.KEY_ALGORITHM_EC,
                ECGenParameterSpec("secp521r1"),
                alg,
                attestationChallenge
            )
            setOf(RS1, RS256, RS384, RS512).contains(alg) -> createKeyPair(
                alias,
                KeyProperties.KEY_ALGORITHM_RSA,
                null,
                alg,
                attestationChallenge
            )
            else -> throw IllegalArgumentException(
                String.format(
                    "alg %s is not supported.",
                    alg.jcaName
                )
            )
        }
    }

    protected abstract fun createSecretKey(alias: String)

    protected abstract fun createKeyPair(
        alias: String,
        algorithm: String,
        algorithmParameterSpec: AlgorithmParameterSpec?,
        signatureAlgorithm: SignatureAlgorithm,
        attestationChallenge: ByteArray?
    )

    private fun containsAlias(alias: String): Boolean {
        return try {
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val element = aliases.nextElement()
                if (element.compareTo(alias, ignoreCase = true) == 0) {
                    return true
                }
            }
            false
        } catch (e: KeyStoreException) {
            throw UnexpectedCheckedException(e)
        }
    }

    companion object {
        private const val ATTESTATION_KEY_ENTRY = "attestationKeyEntry"
        private const val CREDENTIAL_SOURCE_ENCRYPTION_KEY_ENTRY =
            "credentialSourceEncryptionKeyEntry"
        private const val ISSUER_KEY_ENTRY = "issuerKeyEntry"
    }

}