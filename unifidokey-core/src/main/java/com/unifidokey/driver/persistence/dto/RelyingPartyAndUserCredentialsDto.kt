package com.unifidokey.driver.persistence.dto

import androidx.room.Embedded
import androidx.room.Relation
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

data class RelyingPartyAndUserCredentialsDto(
    @field:Embedded(prefix = "rp_")
    val relyingPartyEntity: RelyingPartyEntity,
    @field:Relation(
        parentColumn = "rp_id",
        entityColumn = "rp_id",
        entity = UserCredentialEntity::class
    )
    val userCredentialEntities: List<UserCredentialEntity>
)
