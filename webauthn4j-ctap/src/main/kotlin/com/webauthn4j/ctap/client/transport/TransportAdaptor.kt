package com.webauthn4j.ctap.client.transport

import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.CtapResponseData

interface TransportAdaptor {
    suspend fun <TC : CtapRequest, TR : CtapResponse<TRD>, TRD : CtapResponseData?> send(ctapCommand: TC): TR
}
