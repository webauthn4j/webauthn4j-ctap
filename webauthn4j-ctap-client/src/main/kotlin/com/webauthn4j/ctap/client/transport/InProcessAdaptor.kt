package com.webauthn4j.ctap.client.transport

import com.webauthn4j.ctap.authenticator.transport.internal.InternalTransport
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse

class InProcessAdaptor(
    private val internalTransport: InternalTransport
) : TransportAdaptor {

    override suspend fun <TC : CtapRequest, TR : CtapResponse> send(ctapCommand: TC): TR {
        return internalTransport.send(ctapCommand)
    }
}
