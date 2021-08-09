package com.unifidokey.driver.persistence.dao

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.google.common.truth.Truth
import com.unifidokey.driver.persistence.UnifidoKeyDatabase
import com.unifidokey.driver.persistence.dto.RelyingPartyAndUserCredentialsDto
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
import com.unifidokey.driver.persistence.entity.UserCredentialEntity
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.util.Base64UrlUtil
import com.webauthn4j.util.ECUtil
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.time.Instant

@RunWith(RobolectricTestRunner::class)
class RelyingPartyDaoRobolectricTest {
    private lateinit var target: RelyingPartyDao
    private lateinit var userCredentialDao: UserCredentialDao

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val unifidoKeyDatabase =
            Room.inMemoryDatabaseBuilder(context, UnifidoKeyDatabase::class.java)
                .allowMainThreadQueries().build()
        target = unifidoKeyDatabase.relyingPartyDao
        userCredentialDao = unifidoKeyDatabase.userCredentialDao
    }

    @Test
    fun create_findOne_test() {
        val rpId = "example.com"
        val relyingParty = RelyingPartyEntity(rpId, "example")
        target.create(relyingParty)
        val fetched = target.findOne(rpId)
        Truth.assertThat(fetched!!.relyingPartyEntity.sid).isNotNull()
        Truth.assertThat(fetched.relyingPartyEntity.id).isEqualTo(rpId)
        Truth.assertThat(fetched.relyingPartyEntity.name).isEqualTo("example")
    }

    @Test
    fun findAll_without_credentials_test() {
        val rp0 = RelyingPartyEntity("example.com", "example")
        target.create(rp0)
        val rp1 = RelyingPartyEntity("example.org", "example")
        target.create(rp1)
        val fetched: List<RelyingPartyAndUserCredentialsDto?> = target.findAll()
        Truth.assertThat(fetched).hasSize(2)
    }

    @Test
    fun findAll_with_credentials_test() {
        val rpId = "example.com"
        val rp0 = RelyingPartyEntity(rpId, "example")
        val id = target.create(rp0)
        val credentialId0 = byteArrayOf(0x00, 0x00)
        val credentialId1 = byteArrayOf(0x00, 0x01)
        val keyPair = ECUtil.createKeyPair()
        val userHandle = Base64UrlUtil.decode("")
        val userCredential0 = UserCredentialEntity(
            credentialId0,
            SignatureAlgorithm.ES256,
            keyPair,
            null,
            userHandle,
            "username0",
            "displayName",
            rpId,
            0,
            Instant.parse("2020-01-01T00:00:00.00Z"),
            null,
            "{}"
        )
        val userCredential1 = UserCredentialEntity(
            credentialId1,
            SignatureAlgorithm.ES256,
            keyPair,
            null,
            userHandle,
            "username1",
            "displayName",
            rpId,
            0,
            Instant.parse("2020-01-01T00:00:00.00Z"),
            null,
            "{}"
        )
        userCredentialDao.create(userCredential0)
        userCredentialDao.create(userCredential1)
        val fetched: List<RelyingPartyAndUserCredentialsDto?> = target.findAll()
        Truth.assertThat(fetched).hasSize(1)
        val fetched0 = fetched[0]
        val expectedRp = RelyingPartyEntity(id, rpId, "example")
        Truth.assertThat(fetched0!!.relyingPartyEntity).isEqualTo(expectedRp)
        Truth.assertThat(fetched0.userCredentialEntities).hasSize(2)
    }

    @Test
    fun update_test() {
        val rpId = "example.com"
        val relyingParty = RelyingPartyEntity(rpId, "example")
        val id = target.create(relyingParty)
        val update = RelyingPartyEntity(id, rpId, "updated")
        target.update(update)
        val fetched = target.findOne(rpId)
        Truth.assertThat(fetched!!.relyingPartyEntity).isEqualTo(update)
    }

    @Test
    fun delete_test() {
        val rpId = "example.com"
        val relyingParty = RelyingPartyEntity(rpId, "example")
        target.create(relyingParty)
        target.delete(rpId)
        val fetched = target.findOne(rpId)
        Truth.assertThat(fetched).isNull()
    }

    @Test
    fun deleteAll_test() {
        val rp0 = RelyingPartyEntity("example.com", "example")
        target.create(rp0)
        val rp1 = RelyingPartyEntity("example.org", "example")
        target.create(rp1)
        target.deleteAll()
        val fetched: List<RelyingPartyAndUserCredentialsDto?> = target.findAll()
        Truth.assertThat(fetched).isEmpty()
    }

    //    @Test
    //    public void findAllLiveData_test(){
    //        String rpId = "example.com";
    //        RelyingPartyEntity relyingParty = new RelyingPartyEntity(rpId, "example", "");
    //
    //        LiveData<List<RelyingPartyAndUserCredentialsDto>> fetched = target.findAllLiveData();
    //        target.create(relyingParty);
    //        List<RelyingPartyAndUserCredentialsDto> result = fetched.getValue();
    //    }
}