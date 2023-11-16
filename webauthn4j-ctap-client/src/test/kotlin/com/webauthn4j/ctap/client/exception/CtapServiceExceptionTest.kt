package com.webauthn4j.ctap.client.exception

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertAll

internal class CtapServiceExceptionTest {

    private val cause = RuntimeException()

    @Test
    fun test() {
        val exception1 = CtapClientException("dummy", cause)
        val exception2 = CtapClientException("dummy")
        val exception3 = CtapClientException(cause)
        assertAll(
            { assertThat(exception1.message).isEqualTo("dummy") },
            { assertThat(exception1.cause).isEqualTo(cause) },
            { assertThat(exception2.message).isEqualTo("dummy") },
            { assertThat(exception2.cause).isNull() },
            { assertThat(exception3.message).isEqualTo(cause.toString()) },
            { assertThat(exception3.cause).isEqualTo(cause) }
        )
    }

}