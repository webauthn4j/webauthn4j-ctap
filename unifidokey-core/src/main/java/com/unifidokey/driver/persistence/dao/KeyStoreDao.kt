package com.unifidokey.driver.persistence.dao

import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import java.security.KeyPair
import java.security.PrivateKey
import javax.crypto.SecretKey

interface KeyStoreDao {
    /**
     * Return [SecretKey] for credential source encryption
     *
     * @return [SecretKey] for credential source encryption
     */
    fun findOrCreateEncryptionKey(): SecretKey

    /**
     * Create [KeyPair] for Credential
     *
     * @param alias                alias for [KeyPair]
     * @param attestationChallenge attestation challenge
     * @return [KeyPair] for Credential
     */
    fun createCredentialKeyPair(
        alias: String,
        alg: SignatureAlgorithm,
        attestationChallenge: ByteArray? = null
    ): KeyPair

    /**
     * Return [KeyPair] for Credential
     *
     * @param alias alias for [KeyPair]
     * @return [KeyPair] for Credential
     */
    fun findCredentialKeyPair(alias: String): KeyPair?

    /**
     * Return certificate path as [AttestationCertificatePath] for Credential
     *
     * @param alias for privateKey
     * @return certificate path as [AttestationCertificatePath] for Credential
     */
    fun findCredentialAttestationCertificatePath(alias: String): AttestationCertificatePath?

    /**
     * Return [PrivateKey] for attestation
     *
     * @return [PrivateKey] for attestation
     */
    fun findOrCreateDeviceAttestationPrivateKey(): PrivateKey
    fun findOrCreateDeviceAttestationCertificatePath(): AttestationCertificatePath

    /**
     * Return [PrivateKey] for issuer
     *
     * @return [PrivateKey] for issuer
     */
    fun findOrCreateIssuerPrivateKey(): PrivateKey

    /**
     * Delete entry
     * @param alias alias for the entry
     */
    fun delete(alias: String?)

    /**
     * Delete all keys stored in the keystore
     */
    fun deleteAll()
}