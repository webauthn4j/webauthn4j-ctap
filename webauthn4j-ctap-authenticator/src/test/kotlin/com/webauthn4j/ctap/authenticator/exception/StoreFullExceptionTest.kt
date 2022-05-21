package com.webauthn4j.ctap.authenticator.exception

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test


internal class StoreFullExceptionTest {

    private val cause = RuntimeException()

    @Test
    fun test() {
        val exception1 = StoreFullException("dummy", cause)
        val exception2 = StoreFullException("dummy")
        val exception3 = StoreFullException(cause)
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