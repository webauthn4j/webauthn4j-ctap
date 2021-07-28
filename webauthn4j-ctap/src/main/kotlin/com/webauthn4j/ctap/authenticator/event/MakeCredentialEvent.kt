package com.webauthn4j.ctap.authenticator.event

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

class MakeCredentialEvent : EventBase {

    constructor(
        id: Long?,
        time: Instant,
        rpId: String,
        rpName: String,
        username: String,
        displayName: String,
        details: Map<String, String>
    ) :
            super(
                id,
                time,
                EventType.MakeCredential,
                details.plus(
                    mapOf(
                        Pair("rpId", rpId),
                        Pair("rpName", rpName),
                        Pair("username", username),
                        Pair("displayName", displayName)
                    )
                )
            )

    constructor(
        time: Instant,
        rpId: String,
        rpName: String,
        username: String,
        displayName: String,
        details: Map<String, String>
    ) : this(null, time, rpId, rpName, username, displayName, details)

    @JsonCreator
    constructor(
        @JsonProperty("id") id: Long?,
        @JsonProperty("time") time: Instant,
        @JsonProperty("rpId") rpId: String,
        @JsonProperty("rpName") rpName: String,
        @JsonProperty("username") username: String,
        @JsonProperty("displayName") displayName: String
    ) :
            super(
                id,
                time,
                EventType.MakeCredential,
                mapOf(
                    Pair("rpId", rpId),
                    Pair("rpName", rpName),
                    Pair("username", username),
                    Pair("displayName", displayName)
                )
            )

    val rpId: String
        @JsonIgnore
        get() = get("rpId") as String

    val rpName: String
        @JsonIgnore
        get() = get("rpName") as String

    val displayName: String
        @JsonIgnore
        get() = get("displayName") as String

    override fun toString(): String {
        return "\"%s\" is registered to \"%s\" (\"%s\").".format(displayName, rpName, rpId)
    }


}
