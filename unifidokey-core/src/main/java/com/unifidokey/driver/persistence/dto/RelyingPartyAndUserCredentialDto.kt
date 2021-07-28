package com.unifidokey.driver.persistence.dto

import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

data class RelyingPartyAndUserCredentialDto(
    val relyingParty: RelyingPartyEntity, val userCredential: UserCredentialEntity
)
