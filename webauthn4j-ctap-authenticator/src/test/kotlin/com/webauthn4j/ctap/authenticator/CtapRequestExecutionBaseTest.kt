package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.execution.CtapCommandExecutionBase
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock

@ExperimentalCoroutinesApi
internal class CtapRequestExecutionBaseTest {

    @Test
    fun unexpected_execution_error_test() = runTest {

        val connection = CtapAuthenticator().createSession()
        val target = TestCtapCommandExecution(connection, mock(CtapRequest::class.java))
        target.execute()
    }

    inner class TestCtapCommandExecution(ctapAuthenticatorSession: CtapAuthenticatorSession, ctapRequest: CtapRequest) :
        CtapCommandExecutionBase<CtapRequest, CtapResponse>(ctapAuthenticatorSession, ctapRequest) {

        override val commandName: String
            get() = "TestCtapCommand"

        override suspend fun validate() {
            // nop
        }

        override suspend fun doExecute(): CtapResponse {
            throw RuntimeException()
        }

        @Suppress("UNCHECKED_CAST")
        override fun createErrorResponse(statusCode: CtapStatusCode): CtapResponse {
            return mock(CtapResponse::class.java) as CtapResponse
        }

    }

}