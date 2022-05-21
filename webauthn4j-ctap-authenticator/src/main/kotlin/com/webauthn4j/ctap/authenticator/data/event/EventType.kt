package com.webauthn4j.ctap.authenticator.data.event

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

enum class EventType(val value: String) {
    MakeCredential("makeCredential"),
    GetAssertion("getAssertion"),
    Reset("reset");

    companion object {
        @JsonCreator
        fun create(value: String): EventType {
            return when (value) {
                "makeCredential" -> MakeCredential
                "getAssertion" -> GetAssertion
                "reset" -> Reset
                else -> throw IllegalArgumentException()
            }
        }
    }

    @JsonValue
    override fun toString(): String {
        return value
    }

}