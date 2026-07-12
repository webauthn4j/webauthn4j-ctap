package com.webauthn4j.ctap.authenticator.transport.internal

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.GetAssertionConsentHandler
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentHandler
import com.webauthn4j.ctap.authenticator.UserVerificationCapabilityProvider
import com.webauthn4j.ctap.authenticator.transport.Transport
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse

class InternalTransport(
    ctapAuthenticator: CtapAuthenticator,
    userVerificationCapabilityProvider: UserVerificationCapabilityProvider = ctapAuthenticator.userVerificationCapabilityProvider,
    makeCredentialConsentHandler: MakeCredentialConsentHandler = ctapAuthenticator.makeCredentialConsentHandler,
    getAssertionConsentHandler: GetAssertionConsentHandler = ctapAuthenticator.getAssertionConsentHandler,
) : Transport {

    private val session = ctapAuthenticator.createSession(userVerificationCapabilityProvider, makeCredentialConsentHandler, getAssertionConsentHandler)

    suspend fun <TC : CtapRequest, TR : CtapResponse> send(
        ctapCommand: TC
    ): TR {
        return session.invokeCommand(ctapCommand)
    }
}
