package com.unifidokey.driver.persistence.dao

import androidx.lifecycle.LiveData
import androidx.room.*
import com.unifidokey.driver.persistence.dto.RelyingPartyAndUserCredentialsDto
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity

@Dao
interface RelyingPartyDao {
    @Transaction
    @Query("SELECT relying_party.sid AS rp_sid, relying_party.id AS rp_id, relying_party.name AS rp_name, relying_party.icon AS rp_icon, relying_party.biometric_authentication as rp_biometric_authentication FROM relying_party LEFT JOIN user_credential WHERE relying_party.id = :rpId")
    fun findOne(rpId: String): RelyingPartyAndUserCredentialsDto?

    @Transaction
    @Query("SELECT relying_party.sid AS rp_sid, relying_party.id AS rp_id, relying_party.name AS rp_name, relying_party.icon AS rp_icon, relying_party.biometric_authentication as rp_biometric_authentication FROM relying_party LEFT JOIN user_credential GROUP BY relying_party.id")
    fun findAll(): List<RelyingPartyAndUserCredentialsDto>

    @Transaction
    @Query("SELECT relying_party.sid AS rp_sid, relying_party.id AS rp_id, relying_party.name AS rp_name, relying_party.icon AS rp_icon, relying_party.biometric_authentication as rp_biometric_authentication FROM relying_party LEFT JOIN user_credential GROUP BY relying_party.id")
    fun findAllLiveData(): LiveData<List<RelyingPartyAndUserCredentialsDto>>

    @Insert
    fun create(relyingParty: RelyingPartyEntity): Long

    @Update
    fun update(relyingParty: RelyingPartyEntity)

    @Delete
    fun delete(relyingParty: RelyingPartyEntity)

    @Query("DELETE FROM relying_party WHERE id = :rpId")
    fun delete(rpId: String)

    @Query("DELETE FROM relying_party")
    fun deleteAll()
}