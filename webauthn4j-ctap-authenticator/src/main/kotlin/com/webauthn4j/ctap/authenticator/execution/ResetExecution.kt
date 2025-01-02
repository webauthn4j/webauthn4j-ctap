package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.data.event.ResetEvent
import com.webauthn4j.ctap.authenticator.data.settings.ResetProtectionSetting
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.AuthenticatorResetRequest
import com.webauthn4j.ctap.core.data.AuthenticatorResetResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import org.slf4j.LoggerFactory
import java.time.Instant

/**
 * Reset command execution
 */
class ResetExecution internal constructor(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession,
    authenticatorResetRequest: AuthenticatorResetRequest
) : CtapCommandExecutionBase<AuthenticatorResetRequest, AuthenticatorResetResponse>(
    ctapAuthenticatorSession,
    authenticatorResetRequest
) {

    private val authenticatorPropertyStore: AuthenticatorPropertyStore =
        ctapAuthenticatorSession.authenticatorPropertyStore
    private val logger = LoggerFactory.getLogger(MakeCredentialExecution::class.java)

    override suspend fun validate() {
        // nop
    }

    override suspend fun doExecute(): AuthenticatorResetResponse {
        logger.debug("Processing reset request")
        return when (ctapAuthenticatorSession.resetProtection) {
            ResetProtectionSetting.ENABLED -> AuthenticatorResetResponse(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            else -> {
                ctapAuthenticatorSession.clientPINService.resetVolatilePinRetryCounter()
                authenticatorPropertyStore.clear()
                ctapAuthenticatorSession.publishEvent(ResetEvent(Instant.now()))
                AuthenticatorResetResponse(CtapStatusCode.CTAP2_OK)
            }
        }
    }

    override val commandName: String = "Reset"

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorResetResponse {
        return AuthenticatorResetResponse(statusCode)
    }

}
