package com.webauthn4j.ctap.authenticator.event

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable
import java.time.Instant

class GetAssertionEvent : EventBase {

    constructor(
        id: Long?,
        time: Instant,
        rpId: String,
        rpName: String,
        userCredentials: List<UserCredential>,
        details: Map<String, Serializable>
    ) : super(
        id,
        time,
        EventType.GetAssertion,
        details.plus(
            mapOf(
                Pair("rpId", rpId),
                Pair("rpName", rpName),
                Pair("userCredentials", userCredentials)
            )
        )
    )

    constructor(
        time: Instant,
        rpId: String,
        rpName: String,
        userCredentials: List<UserCredential>,
        details: Map<String, Serializable>
    ) : this(null, time, rpId, rpName, userCredentials, details)

    @JsonCreator
    constructor(
        @JsonProperty("id") id: Long?,
        @JsonProperty("time") time: Instant,
        @JsonProperty("rpId") rpId: String,
        @JsonProperty("rpName") rpName: String,
        @JsonProperty("userCredentials") userCredentials: List<UserCredential>
    ) : super(
        id,
        time,
        EventType.GetAssertion,
        mapOf(Pair("rpId", rpId), Pair("rpName", rpName), Pair("userCredentials", userCredentials))
    )

    val rpId: String
        @JsonIgnore
        get() = get("rpId") as String

    val rpName: String
        @JsonIgnore
        get() = get("rpName") as String

    val userCredentials: List<UserCredential>
        @Suppress("UNCHECKED_CAST")
        @JsonIgnore
        get() = get("userCredentials") as List<UserCredential>

    override fun toString(): String {
        return "\"%s\" is authenticated to \"%s\" (\"%s\").".format(
            userCredentials.first().displayName,
            rpName,
            rpId
        )
    }

    @Suppress("ConvertSecondaryConstructorToPrimary")
    class UserCredential : Serializable {

        @Suppress("JoinDeclarationAndAssignment")
        val username: String

        @Suppress("JoinDeclarationAndAssignment")
        val displayName: String

        @JsonCreator
        constructor(
            @JsonProperty("username") username: String,
            @JsonProperty("displayName") displayName: String
        ) {
            this.username = username
            this.displayName = displayName
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is UserCredential) return false

            if (username != other.username) return false
            if (displayName != other.displayName) return false

            return true
        }

        override fun hashCode(): Int {
            var result = username.hashCode()
            result = 31 * result + displayName.hashCode()
            return result
        }
    }
}