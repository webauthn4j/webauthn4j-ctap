package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.event.ResetEvent
import com.webauthn4j.ctap.authenticator.data.settings.ResetProtectionSetting
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.AuthenticatorResetRequest
import com.webauthn4j.ctap.core.data.AuthenticatorResetResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import org.slf4j.LoggerFactory
import java.time.Instant

class ResetExecution internal constructor(
    private val ctapAuthenticator: CtapAuthenticator,
    authenticatorResetRequest: AuthenticatorResetRequest
) : CtapCommandExecutionBase<AuthenticatorResetRequest, AuthenticatorResetResponse>(
    ctapAuthenticator,
    authenticatorResetRequest
) {

    private val authenticatorPropertyStore: AuthenticatorPropertyStore =
        ctapAuthenticator.authenticatorPropertyStore
    private val logger = LoggerFactory.getLogger(MakeCredentialExecution::class.java)

    override suspend fun validate() {
        // nop
    }

    override suspend fun doExecute(): AuthenticatorResetResponse {
        logger.debug("Processing reset request")
        return when (ctapAuthenticator.resetProtectionSetting) {
            ResetProtectionSetting.ENABLED -> AuthenticatorResetResponse(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
            else -> {
                ctapAuthenticator.clientPINService.resetVolatilePinRetryCounter()
                authenticatorPropertyStore.clear()
                ctapAuthenticator.publishEvent(ResetEvent(Instant.now()))
                AuthenticatorResetResponse(CtapStatusCode.CTAP2_OK)
            }
        }
    }

    override val commandName: String = "Reset"

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorResetResponse {
        return AuthenticatorResetResponse(statusCode)
    }

}
