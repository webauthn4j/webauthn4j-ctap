package com.webauthn4j.ctap.authenticator.transport.internal

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.UserVerificationHandler
import com.webauthn4j.ctap.authenticator.transport.Transport
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse

class InternalTransport(
    ctapAuthenticator: CtapAuthenticator,
    userVerificationHandler: UserVerificationHandler,
) : Transport {

    private val session = ctapAuthenticator.createSession(userVerificationHandler)

    suspend fun <TC : CtapRequest, TR : CtapResponse> send(
        ctapCommand: TC
    ): TR {
        return session.invokeCommand(ctapCommand)
    }
}
