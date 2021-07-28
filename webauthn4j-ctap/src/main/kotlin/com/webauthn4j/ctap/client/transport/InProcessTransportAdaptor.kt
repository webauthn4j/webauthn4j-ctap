package com.webauthn4j.ctap.client.transport

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.CtapResponseData

class InProcessTransportAdaptor(private val ctapAuthenticator: CtapAuthenticator) :
    TransportAdaptor {
    override suspend fun <TC : CtapRequest, TR : CtapResponse<TRD>, TRD : CtapResponseData?> send(
        ctapCommand: TC
    ): TR {
        return ctapAuthenticator.invokeCommand(ctapCommand)
    }
}
