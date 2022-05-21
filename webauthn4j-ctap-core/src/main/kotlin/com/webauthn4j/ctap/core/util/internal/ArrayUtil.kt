package com.webauthn4j.ctap.core.util.internal

object ArrayUtil {
    @JvmStatic
    fun toHexString(value: ByteArray?): String? {
        if (value == null) {
            return null
        }
        val stringBuilder = StringBuilder(value.size * 2)
        for (item in value) stringBuilder.append(String.format("%02x", item))
        return stringBuilder.toString()
    }

    fun indexOf(value: ByteArray, searchValue: Byte): Int {
        for (i in value.indices) {
            if (value[i] == searchValue) {
                return i
            }
        }
        return -1 // not found
    }
}
