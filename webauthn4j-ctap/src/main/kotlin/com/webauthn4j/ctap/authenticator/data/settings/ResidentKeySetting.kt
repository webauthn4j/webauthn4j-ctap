package com.webauthn4j.ctap.authenticator.data.settings

enum class ResidentKeySetting(val value: String) {
    ALWAYS("always"),
    IF_REQUIRED("if-required"),
    NEVER("never");

    companion object {
        @JvmStatic
        fun create(value: String): ResidentKeySetting {
            return when (value) {
                "always" -> ALWAYS
                "if-required" -> IF_REQUIRED
                "never" -> NEVER
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}