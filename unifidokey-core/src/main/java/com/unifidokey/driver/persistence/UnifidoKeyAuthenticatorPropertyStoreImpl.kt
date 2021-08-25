package com.unifidokey.driver.persistence

import com.fasterxml.jackson.core.type.TypeReference
import com.unifidokey.core.adapter.UnifidoKeyAuthenticatorPropertyStore
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.KeyStorageSetting
import com.unifidokey.driver.persistence.dao.KeyStoreDao
import com.unifidokey.driver.persistence.dao.KeyStoreResidentCredentialKey
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
import com.unifidokey.driver.persistence.entity.UserCredentialEntity
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.exception.StoreFullException
import com.webauthn4j.ctap.authenticator.internal.KeyPairUtil.createCredentialKeyPair
import com.webauthn4j.ctap.authenticator.store.ResidentUserCredential
import com.webauthn4j.ctap.authenticator.store.ResidentCredentialKey
import com.webauthn4j.ctap.authenticator.store.CredentialKey
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.security.KeyPair
import java.util.*
import javax.crypto.SecretKey

class UnifidoKeyAuthenticatorPropertyStoreImpl(
    private val relyingPartyDao: RelyingPartyDao,
    private val userCredentialDao: UserCredentialDao,
    private val configManager: ConfigManager,
    private val keyStoreDao: KeyStoreDao
) : UnifidoKeyAuthenticatorPropertyStore {

    override var algorithms = setOf(COSEAlgorithmIdentifier.ES256)
    override var keyStorageSetting = KeyStorageSetting.KEYSTORE

    private val jsonConverter = ObjectConverter().jsonConverter

    /**
     * Create a new [CredentialKey] in the credential storage.
     *
     * @param algorithmIdentifier key algorithm
     * @param clientDataHash      SHA-256 hash of client data, which is used for attestation certificate generation
     * @return user credential key
     */
    override fun createUserCredentialKey(
        algorithmIdentifier: COSEAlgorithmIdentifier,
        clientDataHash: ByteArray
    ): ResidentCredentialKey {
        require(supports(algorithmIdentifier)) { "algorithmIdentifier is not supported." }
        val keyPair: KeyPair
        return when (keyStorageSetting) {
            KeyStorageSetting.KEYSTORE -> {
                val alias = UUID.randomUUID().toString()
                keyPair = keyStoreDao.createCredentialKeyPair(
                    alias,
                    algorithmIdentifier.toSignatureAlgorithm(),
                    clientDataHash
                )
                val attestationCertificatePath =
                    keyStoreDao.findCredentialAttestationCertificatePath(alias)
                KeyStoreResidentCredentialKey(
                    algorithmIdentifier.toSignatureAlgorithm(),
                    alias,
                    keyPair,
                    attestationCertificatePath!!
                )
            }
            KeyStorageSetting.DATABASE -> {
                keyPair = createCredentialKeyPair(algorithmIdentifier)
                ResidentCredentialKey(algorithmIdentifier.toSignatureAlgorithm(), keyPair)
            }
        }
    }

    @Throws(StoreFullException::class)
    override fun saveUserCredential(userCredential: ResidentUserCredential) {
        // create relying party entity if not exists
        // existing relying party will not be updated
        val dto = relyingPartyDao.findOne(userCredential.rpId)
        if (dto == null) {
            val relyingPartyEntity = RelyingPartyEntity(userCredential.rpId, userCredential.rpName)
            relyingPartyDao.create(relyingPartyEntity)
        }


        // save (create or update) user credential entity
        val fetched = userCredentialDao.findOne(userCredential.credentialId)
        val sid = fetched?.sid
        val keyPair: KeyPair?
        val keyAlias: String?
        val credentialKey: CredentialKey = userCredential.credentialKey
        if (credentialKey is KeyStoreResidentCredentialKey) {
            keyPair = null
            keyAlias = credentialKey.keyAlias
        } else {
            keyPair = credentialKey.keyPair
            keyAlias = null
        }
        val detailsAsJson = jsonConverter.writeValueAsString(userCredential.details)
        val userCredentialEntity = UserCredentialEntity(
            sid,
            userCredential.credentialId,
            userCredential.credentialKey.alg,
            keyPair,
            keyAlias,
            userCredential.userHandle,
            userCredential.username,
            userCredential.displayName,
            userCredential.rpId,
            userCredential.counter,
            userCredential.createdAt,
            userCredential.otherUI,
            detailsAsJson
        )
        userCredentialDao.save(userCredentialEntity)
    }

    override fun loadUserCredentials(rpId: String?): List<ResidentUserCredential> {
        if (rpId == null) {
            return emptyList()
        }
        val (relyingPartyEntity, userCredentialEntities) = relyingPartyDao.findOne(rpId)
            ?: return emptyList()
        return userCredentialEntities.map { userCredentialEntity: UserCredentialEntity ->
            val userCredentialKey: ResidentCredentialKey = when {
                userCredentialEntity.keyAlias != null -> { //if keystore
                    val keyPair = keyStoreDao.findCredentialKeyPair(userCredentialEntity.keyAlias)
                    val attestationCertificatePath =
                        keyStoreDao.findCredentialAttestationCertificatePath(userCredentialEntity.keyAlias)
                    KeyStoreResidentCredentialKey(
                        userCredentialEntity.alg,
                        userCredentialEntity.keyAlias,
                        keyPair!!,
                        attestationCertificatePath!!
                    )
                }
                userCredentialEntity.keyPair != null -> {
                    ResidentCredentialKey(userCredentialEntity.alg, userCredentialEntity.keyPair)
                }
                else -> {
                    TODO("throw proper exception")
                }
            }
            val details = jsonConverter.readValue(userCredentialEntity.details, object : TypeReference<Map<String, String>>(){})!!
            ResidentUserCredential(
                userCredentialEntity.credentialId,
                userCredentialKey,
                userCredentialEntity.userHandle,
                userCredentialEntity.username,
                userCredentialEntity.displayName,
                relyingPartyEntity.id,
                relyingPartyEntity.name,
                userCredentialEntity.counter,
                userCredentialEntity.createdAt,
                userCredentialEntity.otherUI,
                details
            )
        }
    }

    override fun removeUserCredential(credentialId: ByteArray) {
        val userCredentialEntity = userCredentialDao.findOne(credentialId)
        if (userCredentialEntity != null) {
            userCredentialDao.delete(credentialId)
            if (userCredentialEntity.keyAlias != null) {
                keyStoreDao.delete(userCredentialEntity.keyAlias)
            }
        }
    }

    override fun supports(alg: COSEAlgorithmIdentifier): Boolean {
        return algorithms.contains(alg)
    }

    override fun loadEncryptionKey(): SecretKey {
        return keyStoreDao.findOrCreateEncryptionKey()
    }

    override fun loadEncryptionIV(): ByteArray {
        return configManager.credentialSourceEncryptionIV.value
    }

    override fun saveClientPIN(clientPIN: ByteArray?) {
        val secretKey = loadEncryptionKey()
        val encrypted =
            CipherUtil.encryptWithAESCBCPKCS5Padding(clientPIN, secretKey, loadEncryptionIV())
        runBlocking {
            launch(Dispatchers.Main.immediate){
                configManager.clientPINEnc.value = encrypted
            }
        }
    }

    override fun loadClientPIN(): ByteArray? {
        val secretKey = loadEncryptionKey()
        val encrypted = configManager.clientPINEnc.value
        return if (encrypted == null) {
            null
        } else {
            CipherUtil.decryptWithAESCBCPKCS5Padding(encrypted, secretKey, loadEncryptionIV())
        }
    }

    override fun loadPINRetries(): Int {
        return configManager.pinRetries.value
    }

    override fun savePINRetries(pinRetries: Int) {
        runBlocking {
            launch(Dispatchers.Main.immediate){
                configManager.pinRetries.value = pinRetries
            }
        }
    }

    override fun loadDeviceWideCounter(): UInt {
        return configManager.deviceWideCounter.value
    }

    override fun saveDeviceWideCounter(deviceWideCounter: UInt) {
        runBlocking {
            launch(Dispatchers.Main.immediate){
                configManager.deviceWideCounter.value = deviceWideCounter
            }
        }
    }

    override fun clear() {
        relyingPartyDao.deleteAll()
        keyStoreDao.deleteAll()
        runBlocking {
            launch(Dispatchers.Main.immediate){
                configManager.pinRetries.reset()
                configManager.clientPINEnc.reset()
                configManager.deviceWideCounter.reset()
            }
        }
    }

}