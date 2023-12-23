package com.unifidokey.core.setting

enum class AllowedAppListSetting(val value: String) {
    STANDARD("standard"),
    LIMITED("limited");

    companion object {
        @JvmStatic
        fun create(value: String): AllowedAppListSetting {
            return when (value) {
                "standard" -> STANDARD
                "limited" -> LIMITED
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}
