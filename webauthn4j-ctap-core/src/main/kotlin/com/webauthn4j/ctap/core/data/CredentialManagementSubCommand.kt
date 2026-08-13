package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

enum class CredentialManagementSubCommand(@get:JsonValue val value: UInt) {

    GET_CREDS_METADATA(0x01u),
    ENUMERATE_RPS_BEGIN(0x02u),
    ENUMERATE_RPS_GET_NEXT_RP(0x03u),
    ENUMERATE_CREDENTIALS_BEGIN(0x04u),
    ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL(0x05u),
    DELETE_CREDENTIAL(0x06u),
    UPDATE_USER_INFORMATION(0x07u);

    companion object {
        @JvmStatic
        @JsonCreator
        fun create(value: UInt): CredentialManagementSubCommand {
            return when (value) {
                0x01u -> GET_CREDS_METADATA
                0x02u -> ENUMERATE_RPS_BEGIN
                0x03u -> ENUMERATE_RPS_GET_NEXT_RP
                0x04u -> ENUMERATE_CREDENTIALS_BEGIN
                0x05u -> ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL
                0x06u -> DELETE_CREDENTIAL
                0x07u -> UPDATE_USER_INFORMATION
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}
