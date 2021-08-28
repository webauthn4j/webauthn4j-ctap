package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.UserCredentialBuilder
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput

interface RegistrationExtensionProcessor : ExtensionProcessor {

    fun processRegistrationExtension(
        context: RegistrationExtensionContext,
        userCredentialBuilder: UserCredentialBuilder,
        extensionOutputsBuilder: AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration)

    fun supportsRegistrationExtension(extension: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>?): Boolean

}
