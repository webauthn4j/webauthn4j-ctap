package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

class PinUvAuthTokenPermissions : AbstractSet<PinUvAuthTokenPermission> {

    private val permissions: Set<PinUvAuthTokenPermission>

    @JsonCreator
    constructor(bitfield: Int) {
        permissions = PinUvAuthTokenPermission.fromBitfield(bitfield)
    }

    constructor(vararg perms: PinUvAuthTokenPermission) {
        permissions = perms.toSet()
    }

    @JsonValue
    fun toBitfield(): Int = PinUvAuthTokenPermission.toBitfield(permissions)

    override val size: Int get() = permissions.size
    override fun iterator(): Iterator<PinUvAuthTokenPermission> = permissions.iterator()
}
