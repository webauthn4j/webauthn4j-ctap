package com.webauthn4j.ctap.client.transport

import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse

interface TransportAdaptor {
    suspend fun <TC : CtapRequest, TR : CtapResponse> send(ctapCommand: TC): TR
}
