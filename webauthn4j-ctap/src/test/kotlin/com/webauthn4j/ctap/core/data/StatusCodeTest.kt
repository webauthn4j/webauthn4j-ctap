package com.webauthn4j.ctap.core.data

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

internal class StatusCodeTest {
    @Test
    fun constructor_can_take_vendor_error_test() {
        val statusCode = StatusCode.create(0xFF.toByte())
        assertThat(statusCode.byte).isEqualTo(0xFF.toByte())
    }

    @Test
    fun create_test() {
        assertThat(StatusCode.create("CTAP2_OK")).isEqualTo(StatusCode.CTAP2_OK)
        assertThat(StatusCode.create("CTAP1_ERR_INVALID_COMMAND")).isEqualTo(StatusCode.CTAP1_ERR_INVALID_COMMAND)
        assertThat(StatusCode.create("CTAP1_ERR_INVALID_PARAMETER")).isEqualTo(StatusCode.CTAP1_ERR_INVALID_PARAMETER)
        assertThat(StatusCode.create("CTAP1_ERR_INVALID_LENGTH")).isEqualTo(StatusCode.CTAP1_ERR_INVALID_LENGTH)
        assertThat(StatusCode.create("CTAP1_ERR_INVALID_SEQ")).isEqualTo(StatusCode.CTAP1_ERR_INVALID_SEQ)
        assertThat(StatusCode.create("CTAP1_ERR_TIMEOUT")).isEqualTo(StatusCode.CTAP1_ERR_TIMEOUT)
        assertThat(StatusCode.create("CTAP1_ERR_CHANNEL_BUSY")).isEqualTo(StatusCode.CTAP1_ERR_CHANNEL_BUSY)
        assertThat(StatusCode.create("CTAP1_ERR_LOCK_REQUIRED")).isEqualTo(StatusCode.CTAP1_ERR_LOCK_REQUIRED)
        assertThat(StatusCode.create("CTAP1_ERR_INVALID_CHANNEL")).isEqualTo(StatusCode.CTAP1_ERR_INVALID_CHANNEL)
        assertThat(StatusCode.create("CTAP2_ERR_CBOR_UNEXPECTED_TYPE")).isEqualTo(StatusCode.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        assertThat(StatusCode.create("CTAP2_ERR_INVALID_CBOR")).isEqualTo(StatusCode.CTAP2_ERR_INVALID_CBOR)
        assertThat(StatusCode.create("CTAP2_ERR_MISSING_PARAMETER")).isEqualTo(StatusCode.CTAP2_ERR_MISSING_PARAMETER)
        assertThat(StatusCode.create("CTAP2_ERR_LIMIT_EXCEEDED")).isEqualTo(StatusCode.CTAP2_ERR_LIMIT_EXCEEDED)
        assertThat(StatusCode.create("CTAP2_ERR_UNSUPPORTED_EXTENSION")).isEqualTo(StatusCode.CTAP2_ERR_UNSUPPORTED_EXTENSION)
        assertThat(StatusCode.create("CTAP2_ERR_CREDENTIAL_EXCLUDED")).isEqualTo(StatusCode.CTAP2_ERR_CREDENTIAL_EXCLUDED)
        assertThat(StatusCode.create("CTAP2_ERR_PROCESSING")).isEqualTo(StatusCode.CTAP2_ERR_PROCESSING)
        assertThat(StatusCode.create("CTAP2_ERR_INVALID_CREDENTIAL")).isEqualTo(StatusCode.CTAP2_ERR_INVALID_CREDENTIAL)
        assertThat(StatusCode.create("CTAP2_ERR_USER_ACTION_PENDING")).isEqualTo(StatusCode.CTAP2_ERR_USER_ACTION_PENDING)
        assertThat(StatusCode.create("CTAP2_ERR_OPERATION_PENDING")).isEqualTo(StatusCode.CTAP2_ERR_OPERATION_PENDING)
        assertThat(StatusCode.create("CTAP2_ERR_NO_OPERATIONS")).isEqualTo(StatusCode.CTAP2_ERR_NO_OPERATIONS)
        assertThat(StatusCode.create("CTAP2_ERR_UNSUPPORTED_ALGORITHM")).isEqualTo(StatusCode.CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        assertThat(StatusCode.create("CTAP2_ERR_OPERATION_DENIED")).isEqualTo(StatusCode.CTAP2_ERR_OPERATION_DENIED)
        assertThat(StatusCode.create("CTAP2_ERR_KEY_STORE_FULL")).isEqualTo(StatusCode.CTAP2_ERR_KEY_STORE_FULL)
        assertThat(StatusCode.create("CTAP2_ERR_NO_OPERATION_PENDING")).isEqualTo(StatusCode.CTAP2_ERR_NO_OPERATION_PENDING)
        assertThat(StatusCode.create("CTAP2_ERR_UNSUPPORTED_OPTION")).isEqualTo(StatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
        assertThat(StatusCode.create("CTAP2_ERR_INVALID_OPTION")).isEqualTo(StatusCode.CTAP2_ERR_INVALID_OPTION)
        assertThat(StatusCode.create("CTAP2_ERR_KEEPALIVE_CANCEL")).isEqualTo(StatusCode.CTAP2_ERR_KEEPALIVE_CANCEL)
        assertThat(StatusCode.create("CTAP2_ERR_NO_CREDENTIALS")).isEqualTo(StatusCode.CTAP2_ERR_NO_CREDENTIALS)
        assertThat(StatusCode.create("CTAP2_ERR_USER_ACTION_TIMEOUT")).isEqualTo(StatusCode.CTAP2_ERR_USER_ACTION_TIMEOUT)
        assertThat(StatusCode.create("CTAP2_ERR_NOT_ALLOWED")).isEqualTo(StatusCode.CTAP2_ERR_NOT_ALLOWED)
        assertThat(StatusCode.create("CTAP2_ERR_PIN_INVALID")).isEqualTo(StatusCode.CTAP2_ERR_PIN_INVALID)
        assertThat(StatusCode.create("CTAP2_ERR_PIN_BLOCKED")).isEqualTo(StatusCode.CTAP2_ERR_PIN_BLOCKED)
        assertThat(StatusCode.create("CTAP2_ERR_PIN_AUTH_INVALID")).isEqualTo(StatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        assertThat(StatusCode.create("CTAP2_ERR_PIN_AUTH_BLOCKED")).isEqualTo(StatusCode.CTAP2_ERR_PIN_AUTH_BLOCKED)
        assertThat(StatusCode.create("CTAP2_ERR_PIN_NOT_SET")).isEqualTo(StatusCode.CTAP2_ERR_PIN_NOT_SET)
        assertThat(StatusCode.create("CTAP2_ERR_PIN_REQUIRED")).isEqualTo(StatusCode.CTAP2_ERR_PIN_REQUIRED)
        assertThat(StatusCode.create("CTAP2_ERR_PIN_POLICY_VIOLATION")).isEqualTo(StatusCode.CTAP2_ERR_PIN_POLICY_VIOLATION)
        assertThat(StatusCode.create("CTAP2_ERR_PIN_TOKEN_EXPIRED")).isEqualTo(StatusCode.CTAP2_ERR_PIN_TOKEN_EXPIRED)
        assertThat(StatusCode.create("CTAP2_ERR_REQUEST_TOO_LARGE")).isEqualTo(StatusCode.CTAP2_ERR_REQUEST_TOO_LARGE)
        assertThat(StatusCode.create("CTAP2_ERR_ACTION_TIMEOUT")).isEqualTo(StatusCode.CTAP2_ERR_ACTION_TIMEOUT)
        assertThat(StatusCode.create("CTAP2_ERR_UP_REQUIRED")).isEqualTo(StatusCode.CTAP2_ERR_UP_REQUIRED)
        assertThat(StatusCode.create("CTAP1_ERR_OTHER")).isEqualTo(StatusCode.CTAP1_ERR_OTHER)
    }

    @Test
    fun getValue_test() {
        val statusCode = StatusCode.create(0x7F.toByte())
        assertThat(statusCode.byte).isEqualTo(0x7F.toByte())
    }

    @Test
    fun toString_test() {
        assertThat(StatusCode.CTAP2_OK.toString()).isEqualTo("CTAP2_OK")
        assertThat(
            StatusCode.create(0xFF.toByte()).toString()
        ).isEqualTo("CTAP2_ERR_UNDEFINED(0xFF)")
    }
}