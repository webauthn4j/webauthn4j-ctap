package com.webauthn4j.ctap.core.data

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class CtapStatusCodeTest {
    @Test
    fun constructor_can_take_vendor_error_test() {
        val statusCode = CtapStatusCode.create(0xFF.toByte())
        assertThat(statusCode.byte).isEqualTo(0xFF.toByte())
    }

    @Test
    fun create_test() {
        assertThat(CtapStatusCode.create("CTAP2_OK")).isEqualTo(CtapStatusCode.CTAP2_OK)
        assertThat(CtapStatusCode.create("CTAP1_ERR_INVALID_COMMAND")).isEqualTo(CtapStatusCode.CTAP1_ERR_INVALID_COMMAND)
        assertThat(CtapStatusCode.create("CTAP1_ERR_INVALID_PARAMETER")).isEqualTo(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
        assertThat(CtapStatusCode.create("CTAP1_ERR_INVALID_LENGTH")).isEqualTo(CtapStatusCode.CTAP1_ERR_INVALID_LENGTH)
        assertThat(CtapStatusCode.create("CTAP1_ERR_INVALID_SEQ")).isEqualTo(CtapStatusCode.CTAP1_ERR_INVALID_SEQ)
        assertThat(CtapStatusCode.create("CTAP1_ERR_TIMEOUT")).isEqualTo(CtapStatusCode.CTAP1_ERR_TIMEOUT)
        assertThat(CtapStatusCode.create("CTAP1_ERR_CHANNEL_BUSY")).isEqualTo(CtapStatusCode.CTAP1_ERR_CHANNEL_BUSY)
        assertThat(CtapStatusCode.create("CTAP1_ERR_LOCK_REQUIRED")).isEqualTo(CtapStatusCode.CTAP1_ERR_LOCK_REQUIRED)
        assertThat(CtapStatusCode.create("CTAP1_ERR_INVALID_CHANNEL")).isEqualTo(CtapStatusCode.CTAP1_ERR_INVALID_CHANNEL)
        assertThat(CtapStatusCode.create("CTAP2_ERR_CBOR_UNEXPECTED_TYPE")).isEqualTo(CtapStatusCode.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        assertThat(CtapStatusCode.create("CTAP2_ERR_INVALID_CBOR")).isEqualTo(CtapStatusCode.CTAP2_ERR_INVALID_CBOR)
        assertThat(CtapStatusCode.create("CTAP2_ERR_MISSING_PARAMETER")).isEqualTo(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)
        assertThat(CtapStatusCode.create("CTAP2_ERR_LIMIT_EXCEEDED")).isEqualTo(CtapStatusCode.CTAP2_ERR_LIMIT_EXCEEDED)
        assertThat(CtapStatusCode.create("CTAP2_ERR_UNSUPPORTED_EXTENSION")).isEqualTo(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_EXTENSION)
        assertThat(CtapStatusCode.create("CTAP2_ERR_CREDENTIAL_EXCLUDED")).isEqualTo(CtapStatusCode.CTAP2_ERR_CREDENTIAL_EXCLUDED)
        assertThat(CtapStatusCode.create("CTAP2_ERR_PROCESSING")).isEqualTo(CtapStatusCode.CTAP2_ERR_PROCESSING)
        assertThat(CtapStatusCode.create("CTAP2_ERR_INVALID_CREDENTIAL")).isEqualTo(CtapStatusCode.CTAP2_ERR_INVALID_CREDENTIAL)
        assertThat(CtapStatusCode.create("CTAP2_ERR_USER_ACTION_PENDING")).isEqualTo(CtapStatusCode.CTAP2_ERR_USER_ACTION_PENDING)
        assertThat(CtapStatusCode.create("CTAP2_ERR_OPERATION_PENDING")).isEqualTo(CtapStatusCode.CTAP2_ERR_OPERATION_PENDING)
        assertThat(CtapStatusCode.create("CTAP2_ERR_NO_OPERATIONS")).isEqualTo(CtapStatusCode.CTAP2_ERR_NO_OPERATIONS)
        assertThat(CtapStatusCode.create("CTAP2_ERR_UNSUPPORTED_ALGORITHM")).isEqualTo(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        assertThat(CtapStatusCode.create("CTAP2_ERR_OPERATION_DENIED")).isEqualTo(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
        assertThat(CtapStatusCode.create("CTAP2_ERR_KEY_STORE_FULL")).isEqualTo(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL)
        assertThat(CtapStatusCode.create("CTAP2_ERR_NO_OPERATION_PENDING")).isEqualTo(CtapStatusCode.CTAP2_ERR_NO_OPERATION_PENDING)
        assertThat(CtapStatusCode.create("CTAP2_ERR_UNSUPPORTED_OPTION")).isEqualTo(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
        assertThat(CtapStatusCode.create("CTAP2_ERR_INVALID_OPTION")).isEqualTo(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
        assertThat(CtapStatusCode.create("CTAP2_ERR_KEEPALIVE_CANCEL")).isEqualTo(CtapStatusCode.CTAP2_ERR_KEEPALIVE_CANCEL)
        assertThat(CtapStatusCode.create("CTAP2_ERR_NO_CREDENTIALS")).isEqualTo(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)
        assertThat(CtapStatusCode.create("CTAP2_ERR_USER_ACTION_TIMEOUT")).isEqualTo(CtapStatusCode.CTAP2_ERR_USER_ACTION_TIMEOUT)
        assertThat(CtapStatusCode.create("CTAP2_ERR_NOT_ALLOWED")).isEqualTo(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        assertThat(CtapStatusCode.create("CTAP2_ERR_PIN_INVALID")).isEqualTo(CtapStatusCode.CTAP2_ERR_PIN_INVALID)
        assertThat(CtapStatusCode.create("CTAP2_ERR_PIN_BLOCKED")).isEqualTo(CtapStatusCode.CTAP2_ERR_PIN_BLOCKED)
        assertThat(CtapStatusCode.create("CTAP2_ERR_PIN_AUTH_INVALID")).isEqualTo(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        assertThat(CtapStatusCode.create("CTAP2_ERR_PIN_AUTH_BLOCKED")).isEqualTo(CtapStatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
        assertThat(CtapStatusCode.create("CTAP2_ERR_PIN_NOT_SET")).isEqualTo(CtapStatusCode.CTAP2_ERR_PIN_NOT_SET)
        assertThat(CtapStatusCode.create("CTAP2_ERR_PIN_REQUIRED")).isEqualTo(CtapStatusCode.CTAP2_ERR_PIN_REQUIRED)
        assertThat(CtapStatusCode.create("CTAP2_ERR_PIN_POLICY_VIOLATION")).isEqualTo(CtapStatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        assertThat(CtapStatusCode.create("CTAP2_ERR_PIN_TOKEN_EXPIRED")).isEqualTo(CtapStatusCode.CTAP2_ERR_PIN_TOKEN_EXPIRED)
        assertThat(CtapStatusCode.create("CTAP2_ERR_REQUEST_TOO_LARGE")).isEqualTo(CtapStatusCode.CTAP2_ERR_REQUEST_TOO_LARGE)
        assertThat(CtapStatusCode.create("CTAP2_ERR_ACTION_TIMEOUT")).isEqualTo(CtapStatusCode.CTAP2_ERR_ACTION_TIMEOUT)
        assertThat(CtapStatusCode.create("CTAP2_ERR_UP_REQUIRED")).isEqualTo(CtapStatusCode.CTAP2_ERR_UP_REQUIRED)
        assertThat(CtapStatusCode.create("CTAP1_ERR_OTHER")).isEqualTo(CtapStatusCode.CTAP1_ERR_OTHER)
    }

    @Test
    fun getValue_test() {
        val statusCode = CtapStatusCode.create(0x7F.toByte())
        assertThat(statusCode.byte).isEqualTo(0x7F.toByte())
    }

    @Test
    fun toString_test() {
        assertThat(CtapStatusCode.CTAP2_OK.toString()).isEqualTo("CTAP2_OK")
        assertThat(
            CtapStatusCode.create(0xFF.toByte()).toString()
        ).isEqualTo("CTAP2_ERR_UNDEFINED(0xFF)")
    }
}