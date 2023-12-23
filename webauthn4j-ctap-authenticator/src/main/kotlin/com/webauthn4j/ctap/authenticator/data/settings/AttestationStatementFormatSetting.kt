package com.webauthn4j.ctap.authenticator.data.settings

import com.fasterxml.jackson.annotation.JsonValue

enum class AttestationStatementFormatSetting(@get:JsonValue val value: String) {
    COMPOUND("compound"),
    ANDROID_KEY("android-key"),
    ANDROID_SAFETYNET("android-safetynet"),
    PACKED("packed"),
    FIDO_U2F("fido-u2f"),
    NONE("none");

    companion object {
        @JvmStatic
        fun create(value: String): AttestationStatementFormatSetting {
            return when (value) {
                "compound" -> COMPOUND
                "android-key" -> ANDROID_KEY
                "android-safetynet" -> ANDROID_SAFETYNET
                "packed" -> PACKED
                "fido-u2f" -> FIDO_U2F
                "none" -> NONE
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}