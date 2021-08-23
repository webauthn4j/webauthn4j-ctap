//package com.unifidokey.driver.persistence.dao
//
//import android.content.Context
//import android.database.sqlite.SQLiteConstraintException
//import androidx.room.Room
//import androidx.test.core.app.ApplicationProvider
//import com.google.common.truth.Truth
//import com.unifidokey.driver.persistence.UnifidoKeyDatabase
//import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
//import com.unifidokey.driver.persistence.entity.UserCredentialEntity
//import com.webauthn4j.data.SignatureAlgorithm
//import com.webauthn4j.util.Base64UrlUtil
//import com.webauthn4j.util.ECUtil
//import org.junit.Before
//import org.junit.Test
//import org.junit.runner.RunWith
//import org.robolectric.RobolectricTestRunner
//import org.robolectric.annotation.Config
//import java.time.Instant
//
//@RunWith(RobolectricTestRunner::class)
//@Config(sdk = [28])
//class UserCredentialDaoRobolectricTest {
//    private lateinit var relyingPartyDao: RelyingPartyDao
//    private lateinit var target: UserCredentialDao
//
//    @Before
//    fun setup() {
//        val context = ApplicationProvider.getApplicationContext<Context>()
//        val unifidoKeyDatabase =
//            Room.inMemoryDatabaseBuilder(context, UnifidoKeyDatabase::class.java)
//                .allowMainThreadQueries().build()
//        relyingPartyDao = unifidoKeyDatabase.relyingPartyDao
//        target = unifidoKeyDatabase.userCredentialDao
//    }
//
//    @Test
//    fun create_findOne_test() {
//        val rpId = "example.com"
//        val relyingParty = RelyingPartyEntity(rpId, "example")
//        val credentialId = Base64UrlUtil.decode("")
//        val keyPair = ECUtil.createKeyPair()
//        val userHandle = Base64UrlUtil.decode("")
//        val userCredential = UserCredentialEntity(
//            credentialId,
//            SignatureAlgorithm.ES256,
//            keyPair,
//            null,
//            userHandle,
//            "username",
//            "displayName",
//            rpId,
//            0,
//            Instant.parse("2020-01-01T00:00:00.00Z"),
//            null,
//            "{}"
//        )
//        relyingPartyDao.create(relyingParty)
//        val id = target.create(userCredential)
//        val fetched = target.findOne(credentialId)
//        val expected = UserCredentialEntity(
//            id,
//            credentialId,
//            SignatureAlgorithm.ES256,
//            keyPair,
//            null,
//            userHandle,
//            "username",
//            "displayName",
//            rpId,
//            0,
//            Instant.parse("2020-01-01T00:00:00.00Z"),
//            null,
//            "{}"
//        )
//        Truth.assertThat(fetched!!.sid).isEqualTo(expected.sid)
//    }
//
//    @Test
//    fun findAll_test() {
//        val rpId = "example.com"
//        val relyingParty = RelyingPartyEntity(rpId, "example")
//        val credentialId0 = byteArrayOf(0x00)
//        val credentialId1 = byteArrayOf(0x01)
//        val keyPair = ECUtil.createKeyPair()
//        val userHandle = Base64UrlUtil.decode("")
//        val userCredential0 = UserCredentialEntity(
//            credentialId0,
//            SignatureAlgorithm.ES256,
//            keyPair,
//            null,
//            userHandle,
//            "username",
//            "displayName",
//            rpId,
//            0,
//            Instant.parse("2020-01-01T00:00:00.00Z"),
//            null,
//            "{}"
//        )
//        val userCredential1 = UserCredentialEntity(
//            credentialId1,
//            SignatureAlgorithm.ES256,
//            keyPair,
//            null,
//            userHandle,
//            "username",
//            "displayName",
//            rpId,
//            0,
//            Instant.parse("2020-01-01T00:00:00.00Z"),
//            null,
//            "{}"
//        )
//        relyingPartyDao.create(relyingParty)
//        target.create(userCredential0)
//        target.create(userCredential1)
//        val fetched = target.findAll()
//        Truth.assertThat(fetched).hasSize(2)
//    }
//
//    @Test(expected = SQLiteConstraintException::class)
//    fun create_without_foreign_entity_test() {
//        val rpId = "example.com"
//        val credentialId = Base64UrlUtil.decode("")
//        val keyPair = ECUtil.createKeyPair()
//        val userHandle = Base64UrlUtil.decode("")
//        val userCredential = UserCredentialEntity(
//            credentialId,
//            SignatureAlgorithm.ES256,
//            keyPair,
//            null,
//            userHandle,
//            "username",
//            "displayName",
//            rpId,
//            0,
//            Instant.parse("2020-01-01T00:00:00.00Z"),
//            null,
//            "{}"
//        )
//        target.create(userCredential)
//    }
//
//    @Test
//    fun update_test() {
//        val rpId = "example.com"
//        val relyingParty = RelyingPartyEntity(rpId, "example")
//        val credentialId = Base64UrlUtil.decode("")
//        val keyPair = ECUtil.createKeyPair()
//        val userHandle = Base64UrlUtil.decode("")
//        val userCredential = UserCredentialEntity(
//            credentialId,
//            SignatureAlgorithm.ES256,
//            keyPair,
//            null,
//            userHandle,
//            "username",
//            "displayName",
//            rpId,
//            0,
//            Instant.parse("2020-01-01T00:00:00.00Z"),
//            null,
//            "{}"
//        )
//        val id = relyingPartyDao.create(relyingParty)
//        target.create(userCredential)
//        val update = UserCredentialEntity(
//            id,
//            credentialId,
//            SignatureAlgorithm.ES256,
//            keyPair,
//            null,
//            userHandle,
//            "username",
//            "update",
//            rpId,
//            0,
//            Instant.parse("2020-01-01T00:00:00.00Z"),
//            null,
//            "{}"
//        )
//        target.update(update)
//        val fetched = target.findOne(credentialId)
//        Truth.assertThat(fetched).isEqualTo(update)
//    }
//
//    @Test
//    fun delete_test() {
//        val rpId = "example.com"
//        val relyingParty = RelyingPartyEntity(rpId, "example")
//        val credentialId = Base64UrlUtil.decode("")
//        val keyPair = ECUtil.createKeyPair()
//        val userHandle = Base64UrlUtil.decode("")
//        val userCredential = UserCredentialEntity(
//            credentialId,
//            SignatureAlgorithm.ES256,
//            keyPair,
//            null,
//            userHandle,
//            "username",
//            "displayName",
//            rpId,
//            0,
//            Instant.parse("2020-01-01T00:00:00.00Z"),
//            null,
//            "{}"
//        )
//        relyingPartyDao.create(relyingParty)
//        val id = target.create(userCredential)
//        val delete = UserCredentialEntity(
//            id,
//            credentialId,
//            SignatureAlgorithm.ES256,
//            keyPair,
//            null,
//            userHandle,
//            "username",
//            "displayName",
//            rpId,
//            0,
//            Instant.parse("2020-01-01T00:00:00.00Z"),
//            null,
//            "{}"
//        )
//        target.delete(delete)
//        val fetched = target.findOne(credentialId)
//        Truth.assertThat(fetched).isNull()
//    }
//}