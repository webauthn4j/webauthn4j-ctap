package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.options.*
import com.webauthn4j.ctap.authenticator.settings.*
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.data.StatusCode
import org.slf4j.LoggerFactory

internal class GetInfoExecution(
    private val ctapAuthenticator: CtapAuthenticator,
    authenticatorGetInfoCommand: AuthenticatorGetInfoRequest
) : CtapCommandExecutionBase<AuthenticatorGetInfoRequest, AuthenticatorGetInfoResponse>(
    authenticatorGetInfoCommand
) {

    private val logger = LoggerFactory.getLogger(GetInfoExecution::class.java)
    override val commandName: String = "GetInfo"

    override suspend fun doExecute(): AuthenticatorGetInfoResponse {
        val plat: PlatformOption = when (ctapAuthenticator.platformSetting) {
            PlatformSetting.CROSS_PLATFORM -> PlatformOption.CROSS_PLATFORM
            PlatformSetting.PLATFORM -> PlatformOption.PLATFORM
        }
        val rk: ResidentKeyOption = when (ctapAuthenticator.residentKeySetting) {
            ResidentKeySetting.ALWAYS, ResidentKeySetting.IF_REQUIRED -> ResidentKeyOption.SUPPORTED
            ResidentKeySetting.NEVER -> ResidentKeyOption.NOT_SUPPORTED
        }
        val clientPin: ClientPINOption? = when (ctapAuthenticator.clientPINSetting) {
            ClientPINSetting.ENABLED -> when {
                ctapAuthenticator.clientPINService.isClientPINReady -> ClientPINOption.SET
                else -> ClientPINOption.NOT_SET
            }
            ClientPINSetting.DISABLED -> ClientPINOption.NOT_SUPPORTED
        }
        val up: UserPresenceOption = when (ctapAuthenticator.userPresenceSetting) {
            UserPresenceSetting.SUPPORTED -> UserPresenceOption.SUPPORTED
            UserPresenceSetting.NOT_SUPPORTED -> UserPresenceOption.NOT_SUPPORTED
        }
        val uv: UserVerificationOption? = when (ctapAuthenticator.userVerificationSetting) {
            UserVerificationSetting.READY -> UserVerificationOption.READY
            UserVerificationSetting.NOT_READY -> UserVerificationOption.NOT_READY
            UserVerificationSetting.NOT_SUPPORTED -> UserVerificationOption.NOT_SUPPORTED
        }
        return AuthenticatorGetInfoResponse(
            StatusCode.CTAP2_OK,
            AuthenticatorGetInfoResponseData(
                CtapAuthenticator.VERSIONS,
                CtapAuthenticator.EXTENSIONS,
                ctapAuthenticator.aaguid,
                AuthenticatorGetInfoResponseData.Options(plat, rk, clientPin, up, uv),
                2048L,
                CtapAuthenticator.PIN_PROTOCOLS
            )
        )
    }

    override fun createErrorResponse(statusCode: StatusCode): AuthenticatorGetInfoResponse {
        return AuthenticatorGetInfoResponse(statusCode)
    }
}