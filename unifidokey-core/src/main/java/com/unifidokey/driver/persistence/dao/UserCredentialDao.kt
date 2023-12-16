package com.unifidokey.driver.persistence.dao

import androidx.room.*
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

@Dao
interface UserCredentialDao {
    /**
     * If [UserCredentialEntity] exists, update the existing [UserCredentialEntity],
     * Otherwise, create the [UserCredentialEntity].
     *
     * @param userCredentialEntity userCredential
     */
    fun save(userCredentialEntity: UserCredentialEntity) {
        val credentialId = userCredentialEntity.credentialId
        val fetched = findOne(credentialId)
        if (fetched == null) {
            create(userCredentialEntity)
        } else {
            update(userCredentialEntity)
        }
    }

    @Query("SELECT * FROM user_credential WHERE credential_id = :credentialId")
    fun findOne(credentialId: ByteArray?): UserCredentialEntity?

    @Query("SELECT * FROM user_credential")
    fun findAll(): List<UserCredentialEntity>

    @Insert
    fun create(userCredential: UserCredentialEntity): Long

    @Update
    fun update(userCredential: UserCredentialEntity)

    @Delete
    fun delete(userCredential: UserCredentialEntity)

    @Query("DELETE FROM user_credential WHERE credential_id = :credentialId")
    fun delete(credentialId: ByteArray)

    @Query("DELETE FROM user_credential")
    fun deleteAll()
}