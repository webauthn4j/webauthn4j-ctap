package com.unifidokey.core.setting

enum class KeepScreenOnSetting(val value: Boolean) {
    ENABLED(true),
    DISABLED(false);

    companion object {
        @JvmStatic
        fun create(value: Boolean): KeepScreenOnSetting {
            return when {
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}