package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.UserCredentialBuilder
import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.data.extension.CredentialProtectionPolicy
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.data.extension.authenticator.CredentialProtectionExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput

// §12.1 Credential Protection (credProtect)
class CredProtectExtensionProcessor :
    RegistrationExtensionProcessor, GetAssertionCredentialFilter, MakeCredentialCredentialFilter {

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

    //spec| §6.2.2 Step 7.4: Iterate through the applicable credentials list, and if credential protection for
    //spec| a credential is marked as userVerificationRequired, and the "uv" bit is false in the response,
    //spec| remove that credential from the applicable credentials list.
    //spec| Step 7.5: Iterate through the applicable credentials list, and if credential protection for
    //spec| a credential is marked as userVerificationOptionalWithCredentialIDList
    //spec| and there is no allowList passed by the client and the "uv" bit is false in the response,
    //spec| remove that credential from the applicable credentials list.
    override fun test(context: GetAssertionCredentialFilterContext): Boolean {
        return when (getPolicy(context.credential)) {
            CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL -> true
            CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST ->
                context.request.allowList != null || context.uvResult
            CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED ->
                context.uvResult
            else -> true
        }
    }

    //spec| §6.1.2 Step 12.2 Else (implying the credential's credProtect value is userVerificationRequired):
    //spec|   12.2.2 Else (implying user verification was not collected in Step 11), remove the credential from
    //spec|   the excludeList and continue parsing the rest of the list.
    override fun test(context: MakeCredentialCredentialFilterContext): Boolean {
        return when (getPolicy(context.credential)) {
            CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED -> context.uvResult
            else -> true
        }
    }
}
