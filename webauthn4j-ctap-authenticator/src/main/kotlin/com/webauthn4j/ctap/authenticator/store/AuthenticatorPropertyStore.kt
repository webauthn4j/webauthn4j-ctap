package com.webauthn4j.ctap.authenticator.store

import com.webauthn4j.ctap.authenticator.data.credential.ResidentCredentialKey
import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import javax.crypto.SecretKey

/**
 * Core interface for authenticator persistence
 *
 * @param <T> user credential extra data
</T> */
interface AuthenticatorPropertyStore {
    /**
     * Create a new [ResidentCredentialKey]. This method doesn't require to persist a credential key.
     *
     * @param algorithmIdentifier key algorithm
     * @param clientDataHash      SHA-256 hash of client data, which is used for attestation certificate generation
     * @return user credential key
     */
    fun createUserCredentialKey(
        algorithmIdentifier: COSEAlgorithmIdentifier,
        clientDataHash: ByteArray
    ): ResidentCredentialKey

    /**
     * Save [ResidentUserCredential]
     * @param userCredential user credential
     * @throws StoreFullException if underling storage is full
     */
    @Throws(StoreFullException::class)
    fun saveUserCredential(userCredential: ResidentUserCredential)

    /**
     * Load [ResidentUserCredential]s by rpId
     *
     * @param rpId rpId for look up key
     * @return user credentials
     */
    fun loadUserCredentials(rpId: String?): List<ResidentUserCredential>

    fun removeUserCredential(credentialId: ByteArray)
    fun supports(alg: COSEAlgorithmIdentifier): Boolean

    /**
     * Load encryption key for credential source
     *
     * @return encryption key for credential source
     */
    fun loadEncryptionKey(): SecretKey

    /**
     * Load encryption iv for credential source
     *
     * @return encryption iv for credential source
     */
    fun loadEncryptionIV(): ByteArray

    /**
     * Save clientPIN
     *
     * @param clientPIN clientPIN
     */
    fun saveClientPIN(clientPIN: ByteArray?)

    /**
     * Load clientPIN
     *
     * @return clientPIN
     */
    fun loadClientPIN(): ByteArray?
    fun savePINRetries(pinRetries: UInt)
    fun loadPINRetries(): UInt

    fun loadDeviceWideCounter(): UInt
    fun saveDeviceWideCounter(deviceWideCounter: UInt)

    /**
     * Clear all user credentials and client PIN
     */
    fun clear()

    var algorithms: Set<COSEAlgorithmIdentifier>
}
