package com.webauthn4j.ctap.authenticator.store

import com.webauthn4j.ctap.authenticator.exception.StoreFullException
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import java.io.Serializable
import javax.crypto.SecretKey

/**
 * Core interface for authenticator persistence
 *
 * @param <T> user credential extra data
</T> */
interface AuthenticatorPropertyStore<T : Serializable?> {
    /**
     * Create a new [ResidentUserCredentialKey]. This method doesn't require to persist a credential key.
     *
     * @param algorithmIdentifier key algorithm
     * @param clientDataHash      SHA-256 hash of client data, which is used for attestation certificate generation
     * @return user credential key
     */
    fun createUserCredentialKey(
        algorithmIdentifier: COSEAlgorithmIdentifier,
        clientDataHash: ByteArray
    ): ResidentUserCredentialKey

    /**
     * Save [ResidentUserCredential]
     * @param userCredential user credential
     * @throws StoreFullException if underling storage is full
     */
    @Throws(StoreFullException::class)
    fun saveUserCredential(userCredential: ResidentUserCredential<T>)

    /**
     * Load [ResidentUserCredential]s by rpId
     *
     * @param rpId rpId for look up key
     * @return user credentials
     */
    fun loadUserCredentials(rpId: String?): List<ResidentUserCredential<T>>

    /**
     * Load single user credential by rpId and userHandle
     *
     * @param rpId       rpId for look up key
     * @param userHandle userHandle for look up key
     * @return user credential
     */
    //TODO: revisit
    fun loadUserCredential(rpId: String?, userHandle: ByteArray): ResidentUserCredential<T>?
    fun removeUserCredential(credentialId: ByteArray)
    fun supports(alg: COSEAlgorithmIdentifier): Boolean

    /**
     * Load encryption key for credential source
     *
     * @return encryption key for credential source
     */
    fun loadEncryptionKey(): SecretKey?

    /**
     * Load encryption iv for credential source
     *
     * @return encryption iv for credential source
     */
    fun loadEncryptionIV(): ByteArray?

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
    fun savePINRetries(pinRetries: Int)
    fun loadPINRetries(): Int

    /**
     * Clear all user credentials and client PIN
     */
    fun clear()

    var algorithms: Set<COSEAlgorithmIdentifier>
}
