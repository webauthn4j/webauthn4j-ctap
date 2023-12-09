package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.execution.ClientPINExecution
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINRequest
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito

internal class ClientPINExecutionTest {

    @Test
    fun createErrorResponse_test() {
        val response = ClientPINExecution(
            Mockito.mock(CtapAuthenticatorSession::class.java),
            Mockito.mock(AuthenticatorClientPINRequest::class.java)
        ).createErrorResponse(CtapStatusCode.CTAP1_ERR_OTHER)
        Assertions.assertThat(response).isInstanceOf(AuthenticatorClientPINResponse::class.java)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP1_ERR_OTHER)
    }
}