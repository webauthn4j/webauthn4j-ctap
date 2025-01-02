package com.webauthn4j.ctap.authenticator.data.event

import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import java.time.Instant

/**
 * Authenticator Event
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes(
    JsonSubTypes.Type(value = MakeCredentialEvent::class, name = "makeCredential"),
    JsonSubTypes.Type(value = GetAssertionEvent::class, name = "getAssertion"),
    JsonSubTypes.Type(value = ResetEvent::class, name = "reset")
)
interface Event {
    /**
     * id
     */
    val id: Long?

    /**
     * time
     */
    val time: Instant

    /**
     * type
     */
    val type: EventType

    operator fun get(key: String): Any?

    override fun equals(other: Any?): Boolean

    override fun hashCode(): Int
}
