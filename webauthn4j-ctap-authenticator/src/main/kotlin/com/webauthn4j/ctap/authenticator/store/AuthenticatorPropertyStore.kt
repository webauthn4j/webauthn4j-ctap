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
    /**
     * Save a generic property by key
     *
     * @param key property key
     * @param value property value, or null to remove
     */
    fun saveProperty(key: String, value: String?) {
        // default no-op for backward compatibility
    }

    /**
     * Load a generic property by key
     *
     * @param key property key
     * @return property value, or null if not found
     */
    fun loadProperty(key: String): String? = null

    fun savePINRetries(pinRetries: UInt) { saveProperty("pinRetries", pinRetries.toString()) }
    fun loadPINRetries(): UInt = loadProperty("pinRetries")?.toUIntOrNull() ?: 8u

    fun saveUVRetries(uvRetries: UInt) { saveProperty("uvRetries", uvRetries.toString()) }
    fun loadUVRetries(): UInt = loadProperty("uvRetries")?.toUIntOrNull() ?: 3u

    fun saveDeviceWideCounter(deviceWideCounter: UInt) { saveProperty("deviceWideCounter", deviceWideCounter.toString()) }
    fun loadDeviceWideCounter(): UInt = loadProperty("deviceWideCounter")?.toUIntOrNull() ?: 0u

    /**
     * Clear all user credentials and client PIN
     */
    fun clear()

    var algorithms: Set<COSEAlgorithmIdentifier>
}
