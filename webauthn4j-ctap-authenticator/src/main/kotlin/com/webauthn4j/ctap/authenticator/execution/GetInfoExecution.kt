package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.data.settings.AttachmentSetting
import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.PlatformOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.UserPresenceOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import org.slf4j.LoggerFactory

/**
 * GetInfo command execution
 */
internal class GetInfoExecution(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession,
    authenticatorGetInfoRequest: AuthenticatorGetInfoRequest
) : CtapCommandExecutionBase<AuthenticatorGetInfoRequest, AuthenticatorGetInfoResponse>(
    ctapAuthenticatorSession,
    authenticatorGetInfoRequest
) {

    private val logger = LoggerFactory.getLogger(GetInfoExecution::class.java)
    override val commandName: String = "GetInfo"

    override suspend fun validate() {
        //nop
    }

    override suspend fun doExecute(): AuthenticatorGetInfoResponse {
        val plat: PlatformOption = when (ctapAuthenticatorSession.platform) {
            AttachmentSetting.CROSS_PLATFORM -> PlatformOption.CROSS_PLATFORM
            AttachmentSetting.PLATFORM -> PlatformOption.PLATFORM
        }
        val rk: ResidentKeyOption = when (ctapAuthenticatorSession.residentKey) {
            ResidentKeySetting.ALWAYS, ResidentKeySetting.IF_REQUIRED -> ResidentKeyOption.SUPPORTED
            ResidentKeySetting.NEVER -> ResidentKeyOption.NOT_SUPPORTED
        }
        val clientPin: ClientPINOption? = when (ctapAuthenticatorSession.clientPIN) {
            ClientPINSetting.ENABLED -> when {
                ctapAuthenticatorSession.clientPINService.isClientPINReady -> ClientPINOption.SET
                else -> ClientPINOption.NOT_SET
            }
            ClientPINSetting.DISABLED -> ClientPINOption.NOT_SUPPORTED
        }
        val up: UserPresenceOption = when (ctapAuthenticatorSession.userPresence) {
            UserPresenceSetting.SUPPORTED -> UserPresenceOption.SUPPORTED
            UserPresenceSetting.NOT_SUPPORTED -> UserPresenceOption.NOT_SUPPORTED
        }
        val uv: UserVerificationOption? = ctapAuthenticatorSession.userVerificationHandler.getUserVerificationOption(null)
        val extensions = ctapAuthenticatorSession.extensionProcessors.map { it.extensionId }
        return AuthenticatorGetInfoResponse(
            CtapStatusCode.CTAP2_OK,
            AuthenticatorGetInfoResponseData(
                CtapAuthenticator.VERSIONS,
                extensions,
                ctapAuthenticatorSession.aaguid,
                AuthenticatorGetInfoResponseData.Options(plat, rk, clientPin, up, uv),
                2048u,
                CtapAuthenticator.PIN_PROTOCOLS,
                null,
                null,
                ctapAuthenticatorSession.transports.toList()
            )
        )
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorGetInfoResponse {
        return AuthenticatorGetInfoResponse(statusCode)
    }
}