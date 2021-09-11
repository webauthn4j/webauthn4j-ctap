package com.webauthn4j.ctap.authenticator.store

import com.webauthn4j.ctap.authenticator.ClientPINService
import com.webauthn4j.ctap.authenticator.exception.CredentialNotFoundException
import com.webauthn4j.ctap.authenticator.exception.RelyingPartyNotFoundException
import com.webauthn4j.ctap.authenticator.internal.KeyPairUtil.createCredentialKeyPair
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.ArrayUtil
import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.function.Consumer
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

open class InMemoryAuthenticatorPropertyStore : AuthenticatorPropertyStore {

    override var algorithms = setOf(COSEAlgorithmIdentifier.ES256)

    private val map: MutableMap<String, MutableMap<ByteArray, ResidentUserCredential>> =
        HashMap()
    private lateinit var credentialSourceEncryptionKey: SecretKey
    private lateinit var credentialSourceEncryptionIV: ByteArray
    private var clientPIN: ByteArray? = null
    private var pinRetries : UInt = 0u
    private var deviceWideCounter = 0u

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
    ): ResidentCredentialKey {
        require(supports(algorithmIdentifier)) { "algorithmIdentifier is not supported." }
        val keyPair = createCredentialKeyPair(algorithmIdentifier)
        return ResidentCredentialKey(algorithmIdentifier.toSignatureAlgorithm(), keyPair)
    }

    override fun saveUserCredential(userCredential: ResidentUserCredential) {
        val rpId = userCredential.rpId
        var userCredentials = map[rpId]
        if (userCredentials == null) {
            userCredentials = HashMap()
            map[rpId] = userCredentials
        }
        userCredentials[userCredential.credentialId] = userCredential
    }

    override fun loadUserCredentials(rpId: String?): List<ResidentUserCredential> {
        if (rpId == null) {
            return emptyList()
        }
        return map[rpId]?.values?.toList() ?: emptyList()
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

    override fun loadEncryptionKey(): SecretKey {
        return credentialSourceEncryptionKey
    }

    override fun loadEncryptionIV(): ByteArray {
        return ArrayUtil.clone(credentialSourceEncryptionIV)
    }

    override fun saveClientPIN(clientPIN: ByteArray?) {
        this.clientPIN = clientPIN
    }

    override fun loadClientPIN(): ByteArray? {
        return ArrayUtil.clone(clientPIN)
    }

    override fun loadPINRetries(): UInt {
        return pinRetries
    }

    override fun loadDeviceWideCounter(): UInt {
        return deviceWideCounter
    }

    override fun saveDeviceWideCounter(deviceWideCounter: UInt) {
        this.deviceWideCounter = deviceWideCounter
    }

    override fun savePINRetries(pinRetries: UInt) {
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