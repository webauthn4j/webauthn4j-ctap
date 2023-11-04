package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.data.settings.PlatformSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResetProtectionSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.data.attestation.authenticator.AAGUID

data class CtapAuthenticatorSettings(
    val aaguid: AAGUID = CtapAuthenticator.AAGUID,
    val platform: PlatformSetting = PlatformSetting.CROSS_PLATFORM,
    val residentKey: ResidentKeySetting = ResidentKeySetting.ALWAYS,
    val clientPIN: ClientPINSetting = ClientPINSetting.ENABLED,
    val resetProtection: ResetProtectionSetting = ResetProtectionSetting.DISABLED,
    val userPresence: UserPresenceSetting = UserPresenceSetting.SUPPORTED,
    val userVerification: UserVerificationSetting = UserVerificationSetting.READY,
    val credentialSelector: CredentialSelectorSetting = CredentialSelectorSetting.AUTHENTICATOR
)
