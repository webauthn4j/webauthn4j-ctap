package com.webauthn4j.ctap.authenticator.store

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Assertions.assertAll
import org.junit.jupiter.api.Test

internal class RelyingPartyNotFoundExceptionTest {
    private val cause = RuntimeException()

    @Test
    fun test() {
        val exception1 = RelyingPartyNotFoundException("dummy", cause)
        val exception2 = RelyingPartyNotFoundException("dummy")
        val exception3 = RelyingPartyNotFoundException(cause)
        assertAll(
            { Assertions.assertThat(exception1.message).isEqualTo("dummy") },
            { Assertions.assertThat(exception1.cause).isEqualTo(cause) },
            { Assertions.assertThat(exception2.message).isEqualTo("dummy") },
            { Assertions.assertThat(exception2.cause).isNull() },
            { Assertions.assertThat(exception3.message).isEqualTo(cause.toString()) },
            { Assertions.assertThat(exception3.cause).isEqualTo(cause) }
        )
    }
}