package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito

internal class GetInfoExecutionTest {

    @Test
    fun createErrorResponse_test() {
        val response = GetInfoExecution(
            Mockito.mock(CtapAuthenticator::class.java),
            Mockito.mock(AuthenticatorGetInfoRequest::class.java)
        ).createErrorResponse(CtapStatusCode.CTAP1_ERR_OTHER)
        Assertions.assertThat(response).isInstanceOf(AuthenticatorGetInfoResponse::class.java)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP1_ERR_OTHER)
    }
}