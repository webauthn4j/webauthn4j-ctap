package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class NoMcGaPermissionsWithClientPinOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val MC_GA_NOT_PERMITTED_FOR_CLIENT_PIN = NoMcGaPermissionsWithClientPinOption(true)

        @JvmField
        val MC_GA_PERMITTED_FOR_CLIENT_PIN = NoMcGaPermissionsWithClientPinOption(false)

        @JvmField
        val NULL: NoMcGaPermissionsWithClientPinOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): NoMcGaPermissionsWithClientPinOption? {
            return when {
                value == null -> NULL
                value -> MC_GA_NOT_PERMITTED_FOR_CLIENT_PIN
                else -> MC_GA_PERMITTED_FOR_CLIENT_PIN
            }
        }
    }
}
