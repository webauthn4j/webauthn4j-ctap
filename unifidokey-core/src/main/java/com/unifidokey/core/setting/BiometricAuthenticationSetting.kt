package com.unifidokey.core.setting

import com.fasterxml.jackson.annotation.JsonValue

enum class BiometricAuthenticationSetting(@get:JsonValue val value: Boolean) {
    ENABLED(true),
    DISABLED(false);

    companion object {
        @JvmStatic
        fun create(value: Boolean): BiometricAuthenticationSetting {
            return when {
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}