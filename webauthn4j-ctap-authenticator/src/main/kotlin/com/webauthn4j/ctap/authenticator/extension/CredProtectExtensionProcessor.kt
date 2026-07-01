package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.UserCredentialBuilder
import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.extension.CredentialProtectionPolicy
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.data.extension.authenticator.CredentialProtectionExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput

class CredProtectExtensionProcessor :
    RegistrationExtensionProcessor, AssertionCredentialFilter, ExcludeListFilter {

    companion object {
        private const val DETAILS_KEY = "credProtect"

        private fun getPolicy(credential: Credential): CredentialProtectionPolicy {
            return credential.details[DETAILS_KEY]
                ?.toByteOrNull()
                ?.let { CredentialProtectionPolicy.create(it) }
                ?: CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL
        }
    }

    override val extensionId: String
        get() = CredentialProtectionExtensionAuthenticatorInput.ID

    override fun supportsRegistrationExtension(
        extension: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>?
    ): Boolean {
        return extension?.credProtect != null
    }

    override fun processRegistrationExtension(
        context: RegistrationExtensionContext,
        userCredentialBuilder: UserCredentialBuilder,
        extensionOutputsBuilder: AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration
    ) {
        val policy = context.makeCredentialRequest.extensions?.credProtect ?: return
        userCredentialBuilder.details().entry(DETAILS_KEY, policy.toByte().toString())
        extensionOutputsBuilder.setCredProtect(policy)
    }

    override fun isAssertionCandidate(
        credential: Credential,
        userVerificationResult: Boolean,
        allowList: List<PublicKeyCredentialDescriptor>?
    ): Boolean {
        return when (getPolicy(credential)) {
            CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL -> true
            CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST ->
                allowList != null || userVerificationResult
            CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED ->
                userVerificationResult
            else -> true
        }
    }

    override fun isExcludeListCandidate(
        credential: Credential,
        pinAuthPresent: Boolean
    ): Boolean {
        return when (getPolicy(credential)) {
            CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED -> pinAuthPresent
            else -> true
        }
    }
}
