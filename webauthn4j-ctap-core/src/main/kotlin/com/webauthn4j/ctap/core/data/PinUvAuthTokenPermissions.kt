package com.webauthn4j.ctap.core.data

class PinUvAuthTokenPermissions private constructor(
    private val permissions: Set<PinUvAuthTokenPermission>
) : AbstractSet<PinUvAuthTokenPermission>() {

    constructor(vararg perms: PinUvAuthTokenPermission) : this(perms.toSet())

    fun toBitfield(): Int = permissions.fold(0) { acc, p -> acc or p.value }

    override val size: Int get() = permissions.size
    override fun iterator(): Iterator<PinUvAuthTokenPermission> = permissions.iterator()

    companion object {
        @JvmStatic
        fun fromBitfield(bitfield: Int): PinUvAuthTokenPermissions {
            return PinUvAuthTokenPermissions(
                PinUvAuthTokenPermission.entries.filter { bitfield and it.value != 0 }.toSet()
            )
        }
    }
}
