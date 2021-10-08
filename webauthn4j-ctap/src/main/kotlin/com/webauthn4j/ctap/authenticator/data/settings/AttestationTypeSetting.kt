package com.webauthn4j.ctap.authenticator.data.settings

import com.fasterxml.jackson.annotation.JsonValue
import com.webauthn4j.data.attestation.statement.AttestationType

enum class AttestationTypeSetting(@get:JsonValue val value: String) {
    BASIC("basic"),
    SELF("self"),
    NONE("none");

    companion object {
        @JvmStatic
        fun create(value: String): AttestationTypeSetting {
            return when (value) {
                "basic" -> BASIC
                "self" -> SELF
                "none" -> NONE
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }

    fun toAttestationType() : AttestationType {
        return when(this){
            BASIC -> AttestationType.BASIC
            SELF -> AttestationType.SELF
            NONE -> AttestationType.NONE
        }
    }
}