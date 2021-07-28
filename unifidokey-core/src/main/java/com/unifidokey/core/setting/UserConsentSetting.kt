package com.unifidokey.core.setting

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue
import com.fasterxml.jackson.databind.exc.InvalidFormatException
import com.webauthn4j.data.AttestationConveyancePreference

enum class UserConsentSetting(@get:JsonValue val value: String) {
    PROMPT_ANYTIME("prompt_anytime"),
    IF_REQUIRED("if_required"),
    CONSENT_AUTOMATICALLY("consent_automatically");

    companion object {
        fun create(value: String): UserConsentSetting {
            return when (value) {
                "prompt_anytime" -> PROMPT_ANYTIME
                "if_required" -> IF_REQUIRED
                "consent_automatically" -> CONSENT_AUTOMATICALLY
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }

        @JsonCreator
        @Throws(InvalidFormatException::class)
        private fun deserialize(value: String): UserConsentSetting {
            return try {
                create(value)
            } catch (e: IllegalArgumentException) {
                throw InvalidFormatException(
                    null,
                    "value is out of range",
                    value,
                    AttestationConveyancePreference::class.java
                )
            }
        }
    }
}