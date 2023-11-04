package com.unifidokey.driver.persistence.converter.room

import androidx.room.TypeConverter
import java.util.Date

class DateConverter {
    @TypeConverter
    fun serialize(value: Date?): Long? {
        return value?.time
    }

    @TypeConverter
    fun deserialize(value: Long?): Date? {
        return when (value) {
            null -> null
            else -> Date(value)
        }
    }
}