package com.webauthn4j.ctap.authenticator.data.settings

import com.webauthn4j.ctap.core.data.options.UserVerificationOption

/**
 * Controls the uv option reported in authenticatorGetInfo.
 *
 * Indicates whether the authenticator has a built-in user verification method (e.g., biometrics, on-device PIN)
 * and whether it has been configured.
 */
enum class UserVerificationSetting(val value: String) {
    /** Built-in user verification is supported and configured (uv=true in GetInfo). */
    READY("ready"),
    /** Built-in user verification is supported but not yet configured (uv=false in GetInfo). */
    NOT_READY("not-ready"),
    /** Built-in user verification is not supported (uv absent from GetInfo). */
    NOT_SUPPORTED("not-supported");

    companion object {
        @JvmStatic
        fun create(value: String): UserVerificationSetting {
            return when (value) {
                "ready" -> READY
                "not-ready" -> NOT_READY
                "not-supported" -> NOT_SUPPORTED
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }

    fun toUserVerificationOption() : UserVerificationOption?{
        return when(this){
            READY -> UserVerificationOption.READY
            NOT_READY -> UserVerificationOption.NOT_READY
            NOT_SUPPORTED -> UserVerificationOption.NOT_SUPPORTED
        }
    }
}