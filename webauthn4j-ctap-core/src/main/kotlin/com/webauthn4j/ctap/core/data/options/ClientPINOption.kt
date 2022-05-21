package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonValue

data class ClientPINOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SET = ClientPINOption(true)

        @JvmField
        val NOT_SET = ClientPINOption(false)

        @JvmField
        val NOT_SUPPORTED: ClientPINOption? = null

        @JvmStatic
        fun create(value: Boolean?): ClientPINOption? {
            return when {
                value == null -> NOT_SUPPORTED
                value -> SET
                else -> NOT_SET
            }
        }
    }
}