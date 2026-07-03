package com.webauthn4j.ctap.authenticator.data.settings

import com.webauthn4j.data.AuthenticatorAttachment

/**
 * Controls the plat option reported in authenticatorGetInfo.
 *
 * Indicates whether the authenticator is a platform authenticator (built into the client device)
 * or a roaming (cross-platform) authenticator.
 */
enum class AttachmentSetting(val value: String) {
    /** The authenticator is built into the client device and cannot be removed. */
    PLATFORM("platform"),
    /** The authenticator is an external roaming device (e.g., USB security key). */
    CROSS_PLATFORM("cross-platform");

    companion object {
        @JvmStatic
        fun create(value: String): AttachmentSetting {
            return when (value) {
                "platform" -> PLATFORM
                "cross-platform" -> CROSS_PLATFORM
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }

    fun toAuthenticatorAttachment(): AuthenticatorAttachment{
        return when(this){
            PLATFORM -> AuthenticatorAttachment.PLATFORM
            CROSS_PLATFORM -> AuthenticatorAttachment.CROSS_PLATFORM
        }
    }
}