package com.unifidokey.driver.persistence

import com.unifidokey.core.adapter.UnifidoKeyAuthenticatorPropertyStore
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.config.PINRetriesConfigProperty
import com.unifidokey.core.setting.KeyStorageSetting
import com.unifidokey.driver.persistence.dao.KeyStoreDao
import com.unifidokey.driver.persistence.dao.KeyStoreResidentUserCredentialKey
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
import com.unifidokey.driver.persistence.entity.UserCredentialEntity
import com.webauthn4j.ctap.authenticator.ClientPINService
import com.webauthn4j.ctap.authenticator.exception.StoreFullException
import com.webauthn4j.ctap.authenticator.internal.KeyPairUtil.createCredentialKeyPair
import com.webauthn4j.ctap.authenticator.store.ResidentUserCredential
import com.webauthn4j.ctap.authenticator.store.ResidentUserCredentialKey
import com.webauthn4j.ctap.authenticator.store.UserCredentialKey
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.Serializable
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


    /**
     * Create a new [UserCredentialKey] in the credential storage.
     *
     * @param algorithmIdentifier key algorithm
     * @param clientDataHash      SHA-256 hash of client data, which is used for attestation certificate generation
     * @return user credential key
     */
    override fun createUserCredentialKey(
        algorithmIdentifier: COSEAlgorithmIdentifier,
        clientDataHash: ByteArray
    ): ResidentUserCredentialKey {
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
                KeyStoreResidentUserCredentialKey(
                    algorithmIdentifier.toSignatureAlgorithm(),
                    alias,
                    keyPair,
                    attestationCertificatePath!!
                )
            }
            KeyStorageSetting.DATABASE -> {
                keyPair = createCredentialKeyPair(algorithmIdentifier)
                ResidentUserCredentialKey(algorithmIdentifier.toSignatureAlgorithm(), keyPair)
            }
        }
    }

    @Throws(StoreFullException::class)
    override fun saveUserCredential(userCredential: ResidentUserCredential<Serializable?>) {
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
        val userCredentialKey: UserCredentialKey = userCredential.userCredentialKey
        if (userCredentialKey is KeyStoreResidentUserCredentialKey) {
            keyPair = null
            keyAlias = userCredentialKey.keyAlias
        } else {
            keyPair = userCredentialKey.keyPair
            keyAlias = null
        }
        val userCredentialEntity = UserCredentialEntity(
            sid,
            userCredential.credentialId,
            userCredential.userCredentialKey.alg,
            keyPair,
            keyAlias,
            userCredential.userHandle,
            userCredential.username,
            userCredential.displayName,
            userCredential.rpId,
            userCredential.counter,
            userCredential.createdAt,
            userCredential.otherUI
        )
        userCredentialDao.save(userCredentialEntity)
    }

    override fun loadUserCredentials(rpId: String?): List<ResidentUserCredential<Serializable?>> {
        if (rpId == null) {
            return emptyList()
        }
        val (relyingPartyEntity, userCredentialEntities) = relyingPartyDao.findOne(rpId)
            ?: return emptyList()
        return userCredentialEntities.map { entity: UserCredentialEntity ->
            val userCredentialKey: ResidentUserCredentialKey = when {
                entity.keyAlias != null -> { //if keystore
                    val keyPair = keyStoreDao.findCredentialKeyPair(entity.keyAlias)
                    val attestationCertificatePath =
                        keyStoreDao.findCredentialAttestationCertificatePath(entity.keyAlias)
                    KeyStoreResidentUserCredentialKey(
                        entity.alg,
                        entity.keyAlias,
                        keyPair!!,
                        attestationCertificatePath!!
                    )
                }
                entity.keyPair != null -> {
                    ResidentUserCredentialKey(entity.alg, entity.keyPair)
                }
                else -> {
                    TODO("throw proper exception")
                }
            }
            ResidentUserCredential(
                entity.credentialId,
                userCredentialKey,
                entity.userHandle,
                entity.username,
                entity.displayName,
                relyingPartyEntity.id,
                relyingPartyEntity.name,
                entity.counter,
                entity.createdAt,
                entity.otherUI
            )
        }
    }

    override fun loadUserCredential(
        rpId: String?,
        userHandle: ByteArray
    ): ResidentUserCredential<Serializable?>? {
        if (rpId == null) {
            return null
        }
        val (relyingPartyEntity, userCredentialEntities) = relyingPartyDao.findOne(rpId)
            ?: return null
        val userCredentialEntity = userCredentialEntities.stream()
            .filter { userCredential: UserCredentialEntity ->
                userCredential.userHandle.contentEquals(
                    userHandle
                )
            }.findFirst().orElse(null)
            ?: return null
        val userCredentialKey: ResidentUserCredentialKey = when {
            userCredentialEntity.keyPair != null -> {
                ResidentUserCredentialKey(userCredentialEntity.alg, userCredentialEntity.keyPair)
            }
            userCredentialEntity.keyAlias != null -> {
                val alias = userCredentialEntity.keyAlias
                val keyPair = keyStoreDao.findCredentialKeyPair(alias)
                val attestationCertificatePath =
                    keyStoreDao.findCredentialAttestationCertificatePath(alias)
                KeyStoreResidentUserCredentialKey(
                    userCredentialEntity.alg,
                    alias,
                    keyPair!!,
                    attestationCertificatePath!!
                )
            }
            else -> TODO("throw proper exception")
        }
        return ResidentUserCredential(
            userCredentialEntity.credentialId,
            userCredentialKey,
            userCredentialEntity.userHandle,
            userCredentialEntity.username,
            userCredentialEntity.displayName,
            relyingPartyEntity.id,
            relyingPartyEntity.name,
            userCredentialEntity.counter,
            userCredentialEntity.createdAt,
            userCredentialEntity.otherUI
        )
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

    override fun clear() {
        relyingPartyDao.deleteAll()
        keyStoreDao.deleteAll()
        runBlocking {
            launch(Dispatchers.Main.immediate){
                configManager.pinRetries.reset()
                configManager.clientPINEnc.reset()
            }
        }
    }

}