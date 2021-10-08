package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.authenticator.data.options.ClientPINOption
import com.webauthn4j.ctap.authenticator.data.options.PlatformOption
import com.webauthn4j.ctap.authenticator.data.options.ResidentKeyOption
import com.webauthn4j.ctap.authenticator.data.options.UserVerificationOption
import com.webauthn4j.data.AuthenticatorAttachment
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.data.UserVerificationRequirement

open class WebAuthnOperationBase(protected val webAuthnClient: WebAuthnClient) {

    protected fun matchByAuthenticatorAttachment(
        authenticatorAttachment: AuthenticatorAttachment?,
        platformOption: PlatformOption?
    ): Boolean {
        return when (authenticatorAttachment) {
            AuthenticatorAttachment.PLATFORM -> when (platformOption) {
                PlatformOption.PLATFORM -> true
                PlatformOption.CROSS_PLATFORM -> false
                PlatformOption.NULL -> true
                else -> false
            }
            AuthenticatorAttachment.CROSS_PLATFORM -> {
                when (platformOption) {
                    PlatformOption.PLATFORM -> false
                    PlatformOption.CROSS_PLATFORM -> true
                    PlatformOption.NULL -> true
                    else -> false
                }
            }
            null -> true
            else -> throw java.lang.IllegalStateException("unexpected authenticatorAttachment.")
        }

    }

    protected fun matchByResidentKey(
        requireResidentKey: Boolean?,
        residentKey: ResidentKeyRequirement?,
        residentKeyOption: ResidentKeyOption?
    ): Boolean {
        return when (residentKey) {
            null -> {
                when (requireResidentKey) {
                    true -> residentKeyOption == ResidentKeyOption.SUPPORTED
                    false -> true
                    else -> true
                }
            }
            ResidentKeyRequirement.REQUIRED -> {
                residentKeyOption == ResidentKeyOption.SUPPORTED
            }
            ResidentKeyRequirement.PREFERRED -> {
                true
            }
            ResidentKeyRequirement.DISCOURAGED -> {
                true
            }
            else -> throw NotImplementedError("unknown option")
        }
    }

    protected fun matchByUserVerification(
        userVerification: UserVerificationRequirement?,
        uv: UserVerificationOption?,
        clientPin: ClientPINOption?
    ): Boolean {
        return when (userVerification) {
            UserVerificationRequirement.REQUIRED -> uv == UserVerificationOption.READY || clientPin == ClientPINOption.SET
            UserVerificationRequirement.PREFERRED, UserVerificationRequirement.DISCOURAGED -> true
            else -> throw IllegalStateException("Unexpected userVerification requirement.")
        }
    }

}
