package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.event.ResetEvent
import com.webauthn4j.ctap.authenticator.settings.ResetProtectionSetting
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.AuthenticatorResetRequest
import com.webauthn4j.ctap.core.data.AuthenticatorResetResponse
import com.webauthn4j.ctap.core.data.StatusCode
import org.slf4j.LoggerFactory
import java.io.Serializable
import java.time.Instant

class ResetExecution internal constructor(
    private val ctapAuthenticator: CtapAuthenticator,
    authenticatorResetCommand: AuthenticatorResetRequest
) : CtapCommandExecutionBase<AuthenticatorResetRequest, AuthenticatorResetResponse>(
    ctapAuthenticator,
    authenticatorResetCommand
) {

    private val authenticatorPropertyStore: AuthenticatorPropertyStore<Serializable?> =
        ctapAuthenticator.authenticatorPropertyStore
    private val logger = LoggerFactory.getLogger(MakeCredentialExecution::class.java)

    override suspend fun doExecute(): AuthenticatorResetResponse {
        logger.debug("Processing reset request")
        return when (ctapAuthenticator.resetProtectionSetting) {
            ResetProtectionSetting.ENABLED -> AuthenticatorResetResponse(StatusCode.CTAP2_ERR_OPERATION_DENIED)
            else -> {
                ctapAuthenticator.clientPINService.resetVolatilePinRetryCounter()
                authenticatorPropertyStore.clear()
                ctapAuthenticator.publishEvent(ResetEvent(Instant.now()))
                AuthenticatorResetResponse(StatusCode.CTAP2_OK)
            }
        }
    }

    override val commandName: String = "Reset"

    override fun createErrorResponse(statusCode: StatusCode): AuthenticatorResetResponse {
        return AuthenticatorResetResponse(statusCode)
    }

}
