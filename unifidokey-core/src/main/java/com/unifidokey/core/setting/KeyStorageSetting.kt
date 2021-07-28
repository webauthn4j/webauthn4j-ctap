package com.unifidokey.core.setting

enum class KeyStorageSetting(val value: String) {
    KEYSTORE("keystore"),
    DATABASE("database");

    companion object {
        @JvmStatic
        fun create(value: String): KeyStorageSetting {
            return when (value) {
                "keystore" -> KEYSTORE
                "database" -> DATABASE
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}