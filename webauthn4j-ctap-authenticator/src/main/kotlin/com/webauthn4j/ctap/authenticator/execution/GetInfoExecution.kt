package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.data.settings.AlwaysUvSetting
import com.webauthn4j.ctap.authenticator.data.settings.AttachmentSetting
import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.MakeCredUvNotRqdSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.options.AlwaysUvOption
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.MakeCredUvNotRqdOption
import com.webauthn4j.ctap.core.data.options.PinUvAuthTokenOption
import com.webauthn4j.ctap.core.data.options.PlatformOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.UserPresenceOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import org.slf4j.LoggerFactory

// §6.4 authenticatorGetInfo (0x04)
//spec| Using this method, platforms can request that the authenticator report a list of its supported
//spec| protocol versions and extensions, its AAGUID, and other aspects of its overall capabilities.
//spec| Platforms should use this information to tailor their command parameters choices.
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
                ctapAuthenticatorSession.isClientPINReady -> ClientPINOption.SET
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
        val uv: UserVerificationOption? = ctapAuthenticatorSession.userVerificationCapabilityProvider.getUserVerificationOption(null)
        //spec| pinUvAuthToken: If pinUvAuthToken is:
        //spec| present and set to true, pinUvAuthToken is supported.
        //spec| present and set to false, or absent, pinUvAuthToken is not supported.
        val pinUvAuthToken: PinUvAuthTokenOption = PinUvAuthTokenOption.SUPPORTED
        // TODO: §6.4 noMcGaPermissionsWithClientPin — mc/ga permission restriction not yet implemented
        // TODO: §6.4 largeBlobs — authenticatorLargeBlobs command not yet implemented
        // TODO: §6.4 ep — enterprise attestation not yet implemented
        // TODO: §6.4 bioEnroll — authenticatorBioEnrollment command not yet implemented
        // TODO: §6.4 userVerificationMgmtPreview — FIDO_2_1_PRE prototype, not yet implemented
        // TODO: §6.4 uvBioEnroll — depends on bioEnroll, not yet implemented
        // TODO: §6.4 authnrCfg — authenticatorConfig command not yet implemented
        // TODO: §6.4 uvAcfg — depends on authnrCfg, not yet implemented
        // TODO: §6.4 credMgmt — authenticatorCredentialManagement command not yet implemented
        // TODO: §6.4 perCredMgmtRO — depends on credMgmt, not yet implemented
        // TODO: §6.4 credentialMgmtPreview — FIDO_2_1_PRE prototype, not yet implemented
        // TODO: §6.4 setMinPINLength — depends on authnrCfg, not yet implemented
        val alwaysUv: AlwaysUvOption? = when (ctapAuthenticatorSession.alwaysUv) {
            AlwaysUvSetting.ENABLED -> AlwaysUvOption.ENABLED
            AlwaysUvSetting.DISABLED -> null
        }
        val makeCredUvNotRqd: MakeCredUvNotRqdOption? = when (ctapAuthenticatorSession.makeCredUvNotRqd) {
            MakeCredUvNotRqdSetting.UV_NOT_REQUIRED -> MakeCredUvNotRqdOption.UV_NOT_REQUIRED
            MakeCredUvNotRqdSetting.UV_REQUIRED -> null
        }
        val extensions = ctapAuthenticatorSession.extensionProcessors.map { it.extensionId }

        // §6.4 algorithms (0x0A)
        val algorithms = ctapAuthenticatorSession.authenticatorPropertyStore.algorithms.map { alg ->
            PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, alg)
        }

        // §6.4 minPINLength (0x0D)
        val minPINLength: UInt? = when (ctapAuthenticatorSession.clientPIN) {
            ClientPINSetting.ENABLED -> ctapAuthenticatorSession.pinUvAuthManager.minPINLength.toUInt()
            ClientPINSetting.DISABLED -> null
        }

        return AuthenticatorGetInfoResponse(
            CtapStatusCode.CTAP2_OK,
            AuthenticatorGetInfoResponseData(
                CtapAuthenticator.VERSIONS,       // versions (0x01): Required
                extensions,                        // extensions (0x02): Optional
                ctapAuthenticatorSession.aaguid,   // aaguid (0x03): Required
                AuthenticatorGetInfoResponseData.Options(
                    plat, rk, clientPin, up, uv,
                    pinUvAuthToken,
                    null, // noMcGaPermissionsWithClientPin
                    null, // largeBlobs
                    null, // ep
                    null, // bioEnroll
                    null, // userVerificationMgmtPreview
                    null, // uvBioEnroll
                    null, // authnrCfg
                    null, // uvAcfg
                    null, // credMgmt
                    null, // perCredMgmtRO
                    null, // credentialMgmtPreview
                    null, // setMinPINLength
                    makeCredUvNotRqd,
                    alwaysUv
                ),                                 // options (0x04): Optional
                2048u,                             // maxMsgSize (0x05): Optional
                ctapAuthenticatorSession.pinProtocols,   // pinUvAuthProtocols (0x06): Optional
                null,                              // maxCredentialCountInList (0x07): Optional
                null,                              // maxCredentialIdLength (0x08): Optional
                ctapAuthenticatorSession.transports, // transports (0x09): Optional
                algorithms,                        // algorithms (0x0A): Optional
                // TODO: §6.4 maxSerializedLargeBlobArray (0x0B) — depends on largeBlobs
                // TODO: §6.4 forcePINChange (0x0C) — depends on authenticatorConfig setMinPINLength
                minPINLength = minPINLength,        // minPINLength (0x0D): Optional
                // TODO: §6.4 firmwareVersion (0x0E)
                // TODO: §6.4 maxCredBlobLength (0x0F) — depends on credBlob extension
                // TODO: §6.4 remainingDiscoverableCredentials (0x14) — store has no capacity concept
            )
        )
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorGetInfoResponse {
        return AuthenticatorGetInfoResponse(statusCode)
    }
}
