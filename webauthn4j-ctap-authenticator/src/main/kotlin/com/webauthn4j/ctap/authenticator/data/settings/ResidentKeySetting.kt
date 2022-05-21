package com.webauthn4j.ctap.authenticator.data.settings

enum class ResidentKeySetting(val value: String) {
    /**
     * Always save as resident-key
     */
    ALWAYS("always"),

    /**
     * If required, save as resident-key
     */
    IF_REQUIRED("if-required"),

    /**
     * Never save as resident-key
     */
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