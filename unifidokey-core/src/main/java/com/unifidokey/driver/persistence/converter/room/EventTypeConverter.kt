package com.unifidokey.driver.persistence.converter.room

import androidx.room.TypeConverter
import com.webauthn4j.ctap.authenticator.data.event.EventType

class EventTypeConverter {
    @TypeConverter
    fun serialize(value: EventType?): String? {
        return value?.toString()
    }

    @TypeConverter
    fun deserialize(value: String?): EventType? {
        return if (value == null) null else EventType.create(value)
    }
}