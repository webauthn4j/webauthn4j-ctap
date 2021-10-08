package com.unifidokey.driver.persistence.converter

import com.unifidokey.driver.persistence.entity.EventEntity
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.data.event.Event

class EventConverter(private val objectConverter: ObjectConverter) {

    fun toEvent(eventEntity: EventEntity): Event {
        val event = objectConverter.jsonConverter.readValue(eventEntity.details, Event::class.java)
        return event!!
    }

    fun toEventEntity(event: Event): EventEntity {
        val details = objectConverter.jsonConverter.writeValueAsString(event)
        return EventEntity(event.id, event.time, event.type, details)
    }
}