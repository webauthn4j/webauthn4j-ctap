package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.util.ArrayUtil
import java.io.Serializable

/**
 * CTAP variant of [PublicKeyCredentialUserEntity] with nullable name and displayName.
 *
 * WebAuthn Level 3 defines name and displayName as required in PublicKeyCredentialUserEntity,
 * but CTAP 2.3 §6.2 requires that "User identifiable information (name, DisplayName, icon)
 * MUST NOT be returned if user verification is not done by the authenticator." This means the
 * authenticator must be able to omit these fields from the CBOR response, which requires them
 * to be nullable — something the webauthn4j-core type does not allow.
 *
 * @see [§5.4.3. User Account Parameters for Credential Generation](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity)
 * @see [§6.2 authenticatorGetAssertion](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion)
 */
class CtapPublicKeyCredentialUserEntity : Serializable {

    /**
     * @param id          id
     * @param name        name
     * @param displayName displayName
     * @param icon        icon
     */
    @JsonCreator
    constructor(
        @JsonProperty("id") id: ByteArray,
        @JsonProperty("name") name: String?,
        @JsonProperty("displayName") displayName: String?,
        @JsonProperty("icon") icon: String?
    ) {
        this.id = ArrayUtil.clone(id)
        this.name = name
        this.displayName = displayName
        this.icon = icon
    }

    // ~ Instance fields
    // ================================================================================================
    val id: ByteArray
        get() = ArrayUtil.clone(field)
    val name: String?
    val displayName: String?
    val icon: String?


    override fun toString(): String {
        return "PublicKeyCredentialUserEntity(id=${HexUtil.encodeToString(id)}, name=$name, displayName=$displayName, icon=$icon)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CtapPublicKeyCredentialUserEntity) return false

        if (!id.contentEquals(other.id)) return false
        if (name != other.name) return false
        if (displayName != other.displayName) return false
        if (icon != other.icon) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.contentHashCode()
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (displayName?.hashCode() ?: 0)
        result = 31 * result + (icon?.hashCode() ?: 0)
        return result
    }


}