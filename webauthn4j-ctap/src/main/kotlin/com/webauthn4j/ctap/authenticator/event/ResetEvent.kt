package com.webauthn4j.ctap.authenticator.event

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

class ResetEvent : EventBase {

    @JsonCreator
    constructor(
        @JsonProperty("id") id: Long?,
        @JsonProperty("time") time: Instant
    ) : super(id, time, EventType.Reset, mapOf())

    constructor(time: Instant) : this(null, time)

    override fun toString(): String {
        return "Authenticator is reset."
    }
}
