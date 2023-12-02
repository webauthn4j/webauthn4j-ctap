package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.Connection
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.PlatformSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
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
    private val connection: Connection,
    authenticatorGetInfoRequest: AuthenticatorGetInfoRequest
) : CtapCommandExecutionBase<AuthenticatorGetInfoRequest, AuthenticatorGetInfoResponse>(
    connection,
    authenticatorGetInfoRequest
) {

    private val logger = LoggerFactory.getLogger(GetInfoExecution::class.java)
    override val commandName: String = "GetInfo"

    override suspend fun validate() {
        //nop
    }

    override suspend fun doExecute(): AuthenticatorGetInfoResponse {
        val plat: PlatformOption = when (connection.platform) {
            PlatformSetting.CROSS_PLATFORM -> PlatformOption.CROSS_PLATFORM
            PlatformSetting.PLATFORM -> PlatformOption.PLATFORM
        }
        val rk: ResidentKeyOption = when (connection.residentKey) {
            ResidentKeySetting.ALWAYS, ResidentKeySetting.IF_REQUIRED -> ResidentKeyOption.SUPPORTED
            ResidentKeySetting.NEVER -> ResidentKeyOption.NOT_SUPPORTED
        }
        val clientPin: ClientPINOption? = when (connection.clientPIN) {
            ClientPINSetting.ENABLED -> when {
                connection.clientPINService.isClientPINReady -> ClientPINOption.SET
                else -> ClientPINOption.NOT_SET
            }
            ClientPINSetting.DISABLED -> ClientPINOption.NOT_SUPPORTED
        }
        val up: UserPresenceOption = when (connection.userPresence) {
            UserPresenceSetting.SUPPORTED -> UserPresenceOption.SUPPORTED
            UserPresenceSetting.NOT_SUPPORTED -> UserPresenceOption.NOT_SUPPORTED
        }
        val uv: UserVerificationOption? = when (connection.userVerification) {
            UserVerificationSetting.READY -> UserVerificationOption.READY
            UserVerificationSetting.NOT_READY -> UserVerificationOption.NOT_READY
            UserVerificationSetting.NOT_SUPPORTED -> UserVerificationOption.NOT_SUPPORTED
        }
        val extensions = connection.extensionProcessors.map { it.extensionId }
        return AuthenticatorGetInfoResponse(
            CtapStatusCode.CTAP2_OK,
            AuthenticatorGetInfoResponseData(
                CtapAuthenticator.VERSIONS,
                extensions,
                connection.aaguid,
                AuthenticatorGetInfoResponseData.Options(plat, rk, clientPin, up, uv),
                2048u,
                CtapAuthenticator.PIN_PROTOCOLS
            )
        )
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorGetInfoResponse {
        return AuthenticatorGetInfoResponse(statusCode)
    }
}