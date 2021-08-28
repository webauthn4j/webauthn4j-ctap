package com.unifidokey.driver.persistence

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.google.common.truth.Truth.assertThat
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.driver.persistence.dao.JCEKSFileKeyStoreDao
import com.unifidokey.driver.persistence.dao.KeyStoreDao
import com.unifidokey.driver.persistence.dao.PreferenceDao
import com.webauthn4j.ctap.authenticator.ClientPINService
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.ResidentCredentialKey
import com.webauthn4j.ctap.authenticator.store.ResidentUserCredential
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.util.ECUtil
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.time.Instant

@RunWith(RobolectricTestRunner::class)
class UnifidoKeyAuthenticatorPropertyStoreImplRobolectricTest {
    private lateinit var target: AuthenticatorPropertyStore

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val unifidoKeyDatabase =
            Room.inMemoryDatabaseBuilder(context, UnifidoKeyDatabase::class.java)
                .allowMainThreadQueries().build()
        val relyingPartyDao = unifidoKeyDatabase.relyingPartyDao
        val userCredentialDao = unifidoKeyDatabase.userCredentialDao
        val preferenceDao = PreferenceDao(context)
        val configManager = ConfigManager(preferenceDao)
        configManager.setup()
        val keyStoreDao: KeyStoreDao = JCEKSFileKeyStoreDao()
        target = UnifidoKeyAuthenticatorPropertyStoreImpl(
            relyingPartyDao,
            userCredentialDao,
            configManager,
            keyStoreDao
        )
    }


//    @Ignore
//    @Test
//    fun createUserCredential_as_nonResidentKey() {
//        val userId = ByteArray(16)
//        val username = "username"
//        val displayName = "displayName"
//        val userIcon = "userIcon"
//        val rpId = "rpId"
//        val rpName = "rpName"
//        val rpIcon = "rpIcon"
//        val counter: Long = 123
//        val clientDataHash = ByteArray(32)
//        val createdAt = Instant.now()
//        val residentKey = false
//        val request: UserCredentialRequest<Serializable> = UserCredentialRequest(
//                PublicKeyCredentialUserEntity(userId, username, displayName, userIcon),
//                PublicKeyCredentialRpEntity(rpId, rpName, rpIcon),
//                counter,
//                createdAt,
//                null,
//                COSEAlgorithmIdentifier.ES256,
//                clientDataHash,
//                residentKey
//        )
//        val userCredential: UserCredential<Serializable> = target.createUserCredential(request)
//        assertThat(userCredential).isNotNull()
//        assertThat(userCredential.getCredentialId()).isNotNull()
//        assertThat(userCredential.getUserCredentialKey()).isNotNull()
//        assertThat(userCredential.getUserHandle()).isEqualTo(userId)
//        assertThat(userCredential.getUsername()).isEqualTo(username)
//        assertThat(userCredential.getDisplayName()).isEqualTo(displayName)
//        assertThat(userCredential.getRpId()).isEqualTo(rpId)
//        assertThat(userCredential.getRpName()).isEqualTo(rpName)
//        assertThat(userCredential.getRpIcon()).isEqualTo(rpIcon)
//        assertThat(userCredential.getCounter()).isEqualTo(counter)
//        assertThat(userCredential.getCreatedAt()).isEqualTo(createdAt)
//        assertThat(userCredential.isResidentKey()).isEqualTo(residentKey)
//    }


//    @Test
//    fun removeUserCredential() {
//        val userId = ByteArray(16)
//        val username = "username"
//        val displayName = "displayName"
//        val userIcon = "userIcon"
//        val rpId = "rpId"
//        val rpName = "rpName"
//        val rpIcon = "rpIcon"
//        val counter: Long = 123
//        val clientDataHash = ByteArray(32)
//        val createdAt = Instant.now()
//        val residentKey = true
//        val request: UserCredentialRequest<Serializable> = UserCredentialRequest(
//                PublicKeyCredentialUserEntity(userId, username, displayName, userIcon),
//                PublicKeyCredentialRpEntity(rpId, rpName, rpIcon),
//                counter,
//                createdAt,
//                null,
//                COSEAlgorithmIdentifier.ES256,
//                clientDataHash,
//                residentKey
//        )
//        val userCredential: UserCredential<Serializable> = target.createUserCredential(request)
//        assertThat(target.loadUserCredential(rpId, userId)).isNotNull()
//        target.removeUserCredential(userCredential)
//        assertThat(target.loadUserCredential(rpId, userId)).isNull()
//    }

//    @Test
//    fun saveUserCredential() {
//        val userId = ByteArray(16)
//        val username = "username"
//        val displayName = "displayName"
//        val userIcon = "userIcon"
//        val rpId = "rpId"
//        val rpName = "rpName"
//        val rpIcon = "rpIcon"
//        val counter: Long = 123
//        val clientDataHash = ByteArray(32)
//        val createdAt = Instant.now()
//        val residentKey = true
//        val request: UserCredentialRequest<Serializable> = UserCredentialRequest(
//                PublicKeyCredentialUserEntity(userId, username, displayName, userIcon),
//                PublicKeyCredentialRpEntity(rpId, rpName, rpIcon),
//                counter,
//                createdAt,
//                null,
//                COSEAlgorithmIdentifier.ES256,
//                clientDataHash,
//                residentKey
//        )
//        val userCredential: UserCredential<Serializable> = target.createUserCredential(request)
//        target.saveUserCredential(userCredential)
//        assertThat(target.loadUserCredential(rpId, userId)).isNotNull()
//    }


    @Test
    fun loadEncryptionKey() {
        val load0 = target.loadEncryptionKey()
        val load1 = target.loadEncryptionKey()
        // multiple load won't return different result
        assertThat(load0).isEqualTo(load1)
    }

    @Test
    fun loadEncryptionIV() {
        val load0 = target.loadEncryptionIV()
        val load1 = target.loadEncryptionIV()
        // multiple load won't return different result
        assertThat(load0).isEqualTo(load1)
    }

    @Test
    fun saveClientPIN_loadClientPIN_test() {
        val data = byteArrayOf(0x01, 0x23)
        target.saveClientPIN(data)
        val loadedData = target.loadClientPIN()
        assertThat(loadedData).isEqualTo(data)
    }

    @Test
    fun savePINRetries_loadPINRetries_test() {
        val pinRetries = 1
        target.savePINRetries(pinRetries)
        val loadedData = target.loadPINRetries()
        assertThat(loadedData).isEqualTo(pinRetries)
    }

    @Test
    fun clear_test() {
        target.savePINRetries(3)
        target.saveClientPIN(ByteArray(32))
        val credentialId = ByteArray(48)
        val userId = ByteArray(16)
        val username = "username"
        val displayName = "displayName"
        val rpId = "rpId"
        val rpName = "rpName"
        val counter: Long = 123
        val createdAt = Instant.now()
        val userCredential = ResidentUserCredential(
            credentialId,
            ResidentCredentialKey(
                SignatureAlgorithm.ES256,
                ECUtil.createKeyPair()
            ),
            userId,
            username,
            displayName,
            rpId,
            rpName,
            counter,
            createdAt,
            null,
            emptyMap()
        )
        target.saveUserCredential(userCredential)
        target.clear()
        assertThat(target.loadPINRetries()).isEqualTo(ClientPINService.MAX_PIN_RETRIES)
        assertThat(target.loadClientPIN()).isNull()
        assertThat(target.loadUserCredentials(rpId)).isEmpty()
    }
}