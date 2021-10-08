package com.webauthn4j.ctap.authenticator.data.event

import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import java.time.Instant

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes(
    JsonSubTypes.Type(value = MakeCredentialEvent::class, name = "makeCredential"),
    JsonSubTypes.Type(value = GetAssertionEvent::class, name = "getAssertion"),
    JsonSubTypes.Type(value = ResetEvent::class, name = "reset")
)
interface Event {
    val id: Long?
    val time: Instant
    val type: EventType

    operator fun get(key: String): Any?

    override fun equals(other: Any?): Boolean

    override fun hashCode(): Int
}