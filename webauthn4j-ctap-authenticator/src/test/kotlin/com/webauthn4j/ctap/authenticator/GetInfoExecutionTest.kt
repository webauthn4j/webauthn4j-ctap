package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.execution.GetInfoExecution
import com.webauthn4j.ctap.authenticator.data.settings.AlwaysUvSetting
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import kotlinx.coroutines.test.runTest

internal class GetInfoExecutionTest {

    @Test
    fun `alwaysUv explicitly disables makeCredUvNotRqd`() = runTest {
        val session = CtapAuthenticator(alwaysUv = AlwaysUvSetting.ENABLED).createSession()

        val response = GetInfoExecution(session, AuthenticatorGetInfoRequest()).execute()

        Assertions.assertThat(response.responseData?.options?.alwaysUv?.value).isTrue()
        Assertions.assertThat(response.responseData?.options?.makeCredUvNotRqd?.value).isFalse()
    }

    @Test
    fun createErrorResponse_test() {
        val response = GetInfoExecution(
            Mockito.mock(CtapAuthenticatorSession::class.java),
            Mockito.mock(AuthenticatorGetInfoRequest::class.java)
        ).createErrorResponse(CtapStatusCode.CTAP1_ERR_OTHER)
        Assertions.assertThat(response).isInstanceOf(AuthenticatorGetInfoResponse::class.java)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP1_ERR_OTHER)
    }
}
