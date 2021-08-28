package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.util.ArrayUtil
import java.io.Serializable

/**
 * [CtapPublicKeyCredentialUserEntity] is a CTAP variant of [PublicKeyCredentialUserEntity]
 *
 * @see [
 * §5.4.3. User Account Parameters for Credential Generation
](https://www.w3.org/TR/webauthn-1/.dictdef-publickeycredentialuserentity) */
class CtapPublicKeyCredentialUserEntity : Serializable {

    /**
     * @param id          id
     * @param name        name
     * @param displayName displayName
     */
    @JsonCreator
    constructor(
        @JsonProperty("id") id: ByteArray,
        @JsonProperty("name") name: String?,
        @JsonProperty("displayName") displayName: String?
    ) {
        this.id = ArrayUtil.clone(id)
        this.name = name
        this.displayName = displayName
    }

    // ~ Instance fields
    // ================================================================================================
    val id: ByteArray
        get() = ArrayUtil.clone(field)
    val name: String?
    val displayName: String?


    override fun toString(): String {
        return "PublicKeyCredentialUserEntity(id=${HexUtil.encodeToString(id)}, displayName=$displayName)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CtapPublicKeyCredentialUserEntity) return false

        if (!id.contentEquals(other.id)) return false
        if (name != other.name) return false
        if (displayName != other.displayName) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.contentHashCode()
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (displayName?.hashCode() ?: 0)
        return result
    }


}