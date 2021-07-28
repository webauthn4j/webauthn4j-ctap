package com.unifidokey.driver.persistence.converter.room

import androidx.room.TypeConverter
import java.time.Instant

class InstantConverter {
    @TypeConverter
    fun toInstant(value: Long?): Instant? {
        return when (value) {
            null -> null
            else -> Instant.ofEpochSecond(value)
        }
    }

    @TypeConverter
    fun toLong(instant: Instant?): Long? {
        return instant?.epochSecond
    }
}