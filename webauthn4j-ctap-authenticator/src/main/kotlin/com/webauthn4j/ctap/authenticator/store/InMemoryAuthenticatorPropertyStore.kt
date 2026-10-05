package com.webauthn4j.ctap.authenticator.store

import com.webauthn4j.ctap.authenticator.data.credential.ResidentCredentialKey
import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
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
    private val properties: MutableMap<String, String> = HashMap()
    private lateinit var credentialSourceEncryptionKey: SecretKey
    private lateinit var credentialSourceEncryptionIV: ByteArray
    private var clientPIN: ByteArray? = null

    init {
        initializeKeys()
    }

    private fun initializeKeys() {
        map.clear()
        properties.clear()
        credentialSourceEncryptionKey = generateAESKey()
        credentialSourceEncryptionIV = generateIV()
        clientPIN = null
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

    override fun saveProperty(key: String, value: String?) {
        if (value != null) {
            properties[key] = value
        } else {
            properties.remove(key)
        }
    }

    override fun loadProperty(key: String): String? {
        return properties[key]
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