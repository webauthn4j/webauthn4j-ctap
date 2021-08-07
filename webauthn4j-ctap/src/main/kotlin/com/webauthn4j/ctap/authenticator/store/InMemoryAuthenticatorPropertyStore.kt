package com.webauthn4j.ctap.authenticator.store

import com.webauthn4j.ctap.authenticator.ClientPINService
import com.webauthn4j.ctap.authenticator.exception.CredentialNotFoundException
import com.webauthn4j.ctap.authenticator.exception.RelyingPartyNotFoundException
import com.webauthn4j.ctap.authenticator.internal.KeyPairUtil.createCredentialKeyPair
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ArrayUtil
import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.io.Serializable
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.function.Consumer
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

open class InMemoryAuthenticatorPropertyStore<T : Serializable?> : AuthenticatorPropertyStore<T> {

    override var algorithms = setOf(COSEAlgorithmIdentifier.ES256)

    private val map: MutableMap<String, MutableMap<ByteArray, ResidentUserCredential<T>>> =
        HashMap()
    private var credentialSourceEncryptionKey: SecretKey? = null
    private lateinit var credentialSourceEncryptionIV: ByteArray
    private var clientPIN: ByteArray? = null
    private var pinRetries = 0

    init {
        initializeKeys()
    }

    private fun initializeKeys() {
        map.clear()
        credentialSourceEncryptionKey = generateAESKey()
        credentialSourceEncryptionIV = generateIV()
        clientPIN = null
        pinRetries = ClientPINService.MAX_PIN_RETRIES
    }

    override fun createUserCredentialKey(
        algorithmIdentifier: COSEAlgorithmIdentifier,
        clientDataHash: ByteArray
    ): ResidentUserCredentialKey {
        require(supports(algorithmIdentifier)) { "algorithmIdentifier is not supported." }
        val keyPair = createCredentialKeyPair(algorithmIdentifier)
        return ResidentUserCredentialKey(algorithmIdentifier.toSignatureAlgorithm(), keyPair)
    }

    override fun saveUserCredential(userCredential: ResidentUserCredential<T>) {
        val rpId = userCredential.rpId
        var userCredentials = map[rpId]
        if (userCredentials == null) {
            userCredentials = HashMap()
            map[rpId] = userCredentials
        }
        userCredentials[userCredential.id] = userCredential
    }

    override fun loadUserCredentials(rpId: String?): List<ResidentUserCredential<T>> {
        if (rpId == null) {
            return emptyList()
        }
        return map[rpId]?.values?.toList() ?: emptyList()
    }

    override fun loadUserCredential(
        rpId: String?,
        userHandle: ByteArray
    ): ResidentUserCredential<T>? {
        if (rpId == null) {
            return null //TODO: revisit: should throw RelyingPartyNotFoundException?
        }
        return loadUserCredentials(rpId).firstOrNull { userCredential: ResidentUserCredential<T> ->
            userCredential.userHandle.contentEquals(
                userHandle
            )
        } //TODO: revisit: should throw CredentialNotFoundException?
    }

    override fun removeUserCredential(credentialId: ByteArray) {
        map.keys.forEach(Consumer { rpId: String ->
            val userCredentials =
                map[rpId] ?: throw RelyingPartyNotFoundException("Relying party not found")
            userCredentials[credentialId]
                ?: throw CredentialNotFoundException("Credential not found")
            userCredentials.remove(credentialId)
        })
    }

    override fun supports(alg: COSEAlgorithmIdentifier): Boolean {
        return algorithms.contains(alg)
    }

    override fun loadEncryptionKey(): SecretKey? {
        return credentialSourceEncryptionKey
    }

    override fun loadEncryptionIV(): ByteArray? {
        return ArrayUtil.clone(credentialSourceEncryptionIV)
    }

    override fun saveClientPIN(clientPIN: ByteArray?) {
        this.clientPIN = clientPIN
    }

    override fun loadClientPIN(): ByteArray? {
        return ArrayUtil.clone(clientPIN)
    }

    override fun loadPINRetries(): Int {
        return pinRetries
    }

    override fun savePINRetries(pinRetries: Int) {
        this.pinRetries = pinRetries
    }

    override fun clear() {
        initializeKeys()
    }

    private fun generateAESKey(): SecretKey {
        return try {
            val keyGen = KeyGenerator.getInstance("AES")
            keyGen.init(256)
            keyGen.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        }
    }

    private fun generateIV(): ByteArray {
        val value = ByteArray(16)
        SecureRandom().nextBytes(value)
        return value
    }

}