package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import java.io.Serializable


/**
 * [CtapPublicKeyCredentialRpEntity] is a CTAP variant of [PublicKeyCredentialRpEntity]
 * Not like [PublicKeyCredentialRpEntity], id is non-null, and name is nullable
 *
 * @see [§5.4.2. Relying Party Parameters for Credential Generation](https://www.w3.org/TR/webauthn-1/.dictdef-publickeycredentialrpentity)
 * @see [§5.1. authenticatorMakeCredential (0x01)](https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorMakeCredential) */
class CtapPublicKeyCredentialRpEntity :Serializable {

    // ~ Instance fields
    // ================================================================================================
    val id: String
    val name: String?
    val icon: String?

    // ~ Constructor
    // ========================================================================================================
    /**
     * @param id   id
     * @param name name
     */
    @JsonCreator
    constructor(
        @JsonProperty("id") id: String,
        @JsonProperty("name") name: String?,
        @JsonProperty("icon") icon: String?
    ) {
        this.id = id
        this.name = name
        this.icon = icon
    }

    constructor(id: String) {
        this.id = id
        this.name = null
        this.icon = null
    }

    override fun toString(): String {
        return "PublicKeyCredentialRpEntity(id=${id}, name=$name, icon=$icon)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CtapPublicKeyCredentialRpEntity) return false

        if (id != other.id) return false
        if (name != other.name) return false
        if (icon != other.icon) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (icon?.hashCode() ?: 0)
        return result
    }


}
