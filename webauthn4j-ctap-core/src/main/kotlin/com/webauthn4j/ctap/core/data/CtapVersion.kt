package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class CtapVersion(@get:JsonValue val versionString: String, val major: Int, val minor: Int) {

    companion object {
        val U2F_V2 = CtapVersion("U2F_V2", 1, 0)
        val FIDO_2_0 = CtapVersion("FIDO_2_0", 1, 0)
        val FIDO_2_1_PRE = CtapVersion("FIDO_2_1_PRE", 1, 0)
        val FIDO_2_1 = CtapVersion("FIDO_2_1", 1, 1)
        val FIDO_2_3 = CtapVersion("FIDO_2_3", 1, 3)

        @JvmStatic
        @JsonCreator
        fun create(value: String): CtapVersion {
            return when (value) {
                U2F_V2.versionString -> U2F_V2
                FIDO_2_0.versionString -> FIDO_2_0
                FIDO_2_1_PRE.versionString -> FIDO_2_1_PRE
                FIDO_2_1.versionString -> FIDO_2_1
                FIDO_2_3.versionString -> FIDO_2_3
                else -> CtapVersion(value, 0, 0)
            }
        }
    }
}
