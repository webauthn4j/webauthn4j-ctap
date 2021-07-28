package com.unifidokey.driver.persistence.dto

import androidx.room.TypeConverter
import com.webauthn4j.converter.util.ObjectConverter
import java.io.Serializable

class SerializableConverter {
    private val jsonConverter = ObjectConverter().jsonConverter

    @TypeConverter
    fun serialize(value: Serializable?): String? {
        return value?.let { jsonConverter.writeValueAsString(it) }
    }

    @TypeConverter
    fun deserialize(value: String?): Serializable? {
        return value?.let { jsonConverter.readValue(it, Serializable::class.java) }
    }
}
