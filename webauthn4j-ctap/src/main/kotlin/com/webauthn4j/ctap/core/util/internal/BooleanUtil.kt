package com.webauthn4j.ctap.core.util.internal

object BooleanUtil {
    @JvmStatic
    fun isTrue(value: Boolean?): Boolean {
        return value != null && value
    }

    fun isNotTrue(value: Boolean?): Boolean {
        return value == null || !value
    }
}
