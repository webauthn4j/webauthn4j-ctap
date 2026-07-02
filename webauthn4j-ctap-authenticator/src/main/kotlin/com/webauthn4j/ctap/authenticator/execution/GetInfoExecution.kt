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

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo">5.4. authenticatorGetInfo</a>
//spec| Using this method, the host can request that the authenticator report a list of all supported
//spec| protocol versions, supported extensions, AAGUID of the device, and its capabilities.
//spec| This method takes no inputs.
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
        //spec| plat: platform device: Indicates that the device is attached to the client and therefore
        //spec| can't be removed and used on another client.
        val plat: PlatformOption = when (ctapAuthenticatorSession.platform) {
            AttachmentSetting.CROSS_PLATFORM -> PlatformOption.CROSS_PLATFORM
            AttachmentSetting.PLATFORM -> PlatformOption.PLATFORM
        }
        //spec| rk: resident key: Indicates that the device is capable of storing keys on the device
        //spec| itself and therefore can satisfy the authenticatorGetAssertion request with allowList
        //spec| parameter not specified or empty.
        val rk: ResidentKeyOption = when (ctapAuthenticatorSession.residentKey) {
            ResidentKeySetting.ALWAYS, ResidentKeySetting.IF_REQUIRED -> ResidentKeyOption.SUPPORTED
            ResidentKeySetting.NEVER -> ResidentKeyOption.NOT_SUPPORTED
        }
        //spec| clientPin: Client PIN:
        //spec| If present and set to true, it indicates that the device is capable of accepting a PIN
        //spec| from the client and PIN has been set.
        //spec| If present and set to false, it indicates that the device is capable of accepting a PIN
        //spec| from the client and PIN has not been set yet.
        //spec| If absent, it indicates that the device is not capable of accepting a PIN from the client.
        //spec| Client PIN is one of the ways to do user verification.
        val clientPin: ClientPINOption? = when (ctapAuthenticatorSession.clientPIN) {
            ClientPINSetting.ENABLED -> when {
                ctapAuthenticatorSession.pinUvAuthService.isClientPINReady -> ClientPINOption.SET
                else -> ClientPINOption.NOT_SET
            }
            ClientPINSetting.DISABLED -> ClientPINOption.NOT_SUPPORTED
        }
        //spec| up: user presence: Indicates that the device is capable of testing user presence.
        val up: UserPresenceOption = when (ctapAuthenticatorSession.userPresence) {
            UserPresenceSetting.SUPPORTED -> UserPresenceOption.SUPPORTED
            UserPresenceSetting.NOT_SUPPORTED -> UserPresenceOption.NOT_SUPPORTED
        }
        //spec| uv: user verification: Indicates that the device is capable of verifying the user within
        //spec| itself. For example, devices with UI, biometrics fall into this category.
        //spec| If present and set to true, it indicates that the device is capable of user verification
        //spec| within itself and has been configured.
        //spec| If present and set to false, it indicates that the device is capable of user verification
        //spec| within itself and has not been yet configured. For example, a biometric device that has
        //spec| not yet been configured will return this parameter set to false.
        //spec| If absent, it indicates that the device is not capable of user verification within itself.
        //spec| A device that can only do Client PIN will not return the "uv" parameter.
        val uv: UserVerificationOption? = ctapAuthenticatorSession.userVerificationHandler.getUserVerificationOption(null)
        val extensions = ctapAuthenticatorSession.extensionProcessors.map { it.extensionId }
        return AuthenticatorGetInfoResponse(
            CtapStatusCode.CTAP2_OK,
            AuthenticatorGetInfoResponseData(
                CtapAuthenticator.VERSIONS,       // versions (0x01): Required
                extensions,                        // extensions (0x02): Optional
                ctapAuthenticatorSession.aaguid,   // aaguid (0x03): Required
                AuthenticatorGetInfoResponseData.Options(plat, rk, clientPin, up, uv), // options (0x04): Optional
                2048u,                             // maxMsgSize (0x05): Optional
                ctapAuthenticatorSession.pinProtocols,   // pinProtocols (0x06): Optional
                null,
                null,
                ctapAuthenticatorSession.transports
            )
        )
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorGetInfoResponse {
        return AuthenticatorGetInfoResponse(statusCode)
    }
}
