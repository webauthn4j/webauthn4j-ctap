package com.webauthn4j.ctap.client.transport

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse

class InProcessTransportAdaptor(private val ctapAuthenticatorSession: CtapAuthenticatorSession) :
    TransportAdaptor {
    override suspend fun <TC : CtapRequest, TR : CtapResponse> send(
        ctapCommand: TC
    ): TR {
        return ctapAuthenticatorSession.invokeCommand(ctapCommand)
    }
}
