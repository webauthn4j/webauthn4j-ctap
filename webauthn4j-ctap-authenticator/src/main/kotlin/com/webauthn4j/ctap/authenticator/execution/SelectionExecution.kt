package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.core.data.AuthenticatorSelectionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorSelectionResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import org.slf4j.LoggerFactory

class SelectionExecution internal constructor(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession,
    authenticatorSelectionRequest: AuthenticatorSelectionRequest
) : CtapCommandExecutionBase<AuthenticatorSelectionRequest, AuthenticatorSelectionResponse>(
    ctapAuthenticatorSession,
    authenticatorSelectionRequest
) {

    private val logger = LoggerFactory.getLogger(SelectionExecution::class.java)

    override suspend fun validate() {
        // nop
    }

    override suspend fun doExecute(): AuthenticatorSelectionResponse {
        logger.debug("Processing selection request")
        val approved = ctapAuthenticatorSession.withUserPresenceWait {
            ctapAuthenticatorSession.selectionHandler.onSelectionRequested()
        }
        return if (approved) {
            AuthenticatorSelectionResponse(CtapStatusCode.CTAP2_OK)
        } else {
            AuthenticatorSelectionResponse(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
        }
    }

    override val commandName: String = "Selection"

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorSelectionResponse {
        return AuthenticatorSelectionResponse(statusCode)
    }
}
