package com.webauthn4j.ctap.authenticator.data.settings

import com.webauthn4j.data.AuthenticatorAttachment

enum class AttachmentSetting(val value: String) {
    PLATFORM("platform"),
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