package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs

interface AuthenticationExtensionProcessor : ExtensionProcessor {

    fun processAuthenticationExtension(
        context: AuthenticationExtensionContext,
        outputsBuilder: AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication
    )

    fun supportsAuthenticationExtension(extensions: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>?): Boolean
}