package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.AuthenticatorResetRequest
import com.webauthn4j.ctap.core.data.AuthenticatorResetResponse
import com.webauthn4j.ctap.core.data.StatusCode
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock

internal class ResetExecutionTest {

    @Test
    fun createErrorResponse_test() {
        val response = ResetExecution(
            mock(CtapAuthenticator::class.java),
            mock(AuthenticatorResetRequest::class.java)
        ).createErrorResponse(StatusCode.CTAP1_ERR_OTHER)
        assertThat(response).isInstanceOf(AuthenticatorResetResponse::class.java)
        assertThat(response.statusCode).isEqualTo(StatusCode.CTAP1_ERR_OTHER)
    }

}