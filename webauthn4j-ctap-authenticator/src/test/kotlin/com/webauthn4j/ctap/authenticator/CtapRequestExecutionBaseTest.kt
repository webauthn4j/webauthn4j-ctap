package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions.assertThatCode
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock

@ExperimentalCoroutinesApi
internal class CtapRequestExecutionBaseTest {

    @Test
    fun unexpected_execution_error_test() = runBlockingTest {

        val ctapAuthenticator = CtapAuthenticator()
        val target = TestCtapCommandExecution(ctapAuthenticator, mock(CtapRequest::class.java))
        assertThatCode {
            runBlockingTest {
                target.execute()
            }
        }.doesNotThrowAnyException()
    }

    inner class TestCtapCommandExecution(ctapAuthenticator: CtapAuthenticator, ctapRequest: CtapRequest) :
        CtapCommandExecutionBase<CtapRequest, CtapResponse>(ctapAuthenticator, ctapRequest) {

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