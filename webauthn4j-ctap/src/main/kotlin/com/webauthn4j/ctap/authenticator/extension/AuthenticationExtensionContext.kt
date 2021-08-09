package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.store.UserCredential
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest

data class AuthenticationExtensionContext(
    val ctapAuthenticator: CtapAuthenticator,
    val getAssertionRequest: AuthenticatorGetAssertionRequest,
    val userCredential: UserCredential,
    val userVerificationPlan: Boolean,
    val userPresencePlan: Boolean
) {

}