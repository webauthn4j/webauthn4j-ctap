package com.unifidokey.driver.persistence.converter.room

import androidx.room.TypeConverter
import java.util.*

class UUIDConverter {
    @TypeConverter
    fun serialize(value: UUID?): String? {
        return value?.toString()
    }

    @TypeConverter
    fun deserialize(value: String?): UUID? {
        return if (value == null) null else UUID.fromString(value)
    }
}