package com.unifidokey.driver.persistence.converter.room

import androidx.room.TypeConverter
import com.webauthn4j.util.Base64UrlUtil

class ByteArrayConverter {
    @TypeConverter
    fun serialize(value: ByteArray?): String? {
        return when (value) {
            null -> null
            else -> Base64UrlUtil.encodeToString(value)
        }
    }

    @TypeConverter
    fun deserialize(value: String?): ByteArray? {
        return when (value) {
            null -> null
            else -> Base64UrlUtil.decode(value)
        }
    }
}