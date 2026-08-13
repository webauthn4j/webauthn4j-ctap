package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import java.io.Serializable


/**
 * CTAP variant of [PublicKeyCredentialRpEntity] with non-null id and nullable name.
 *
 * In CTAP, the RP ID is always present (non-null) in authenticatorMakeCredential requests
 * and authenticatorCredentialManagement responses, whereas WebAuthn's PublicKeyCredentialRpEntity
 * treats id as optional. Additionally, CTAP allows name to be nullable (e.g., in credential
 * management RP enumeration responses where only the id is required).
 *
 * @see [§5.4.2. Relying Party Parameters for Credential Generation](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity)
 * @see [§6.1 authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential)
 */
class CtapPublicKeyCredentialRpEntity : Serializable {

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
