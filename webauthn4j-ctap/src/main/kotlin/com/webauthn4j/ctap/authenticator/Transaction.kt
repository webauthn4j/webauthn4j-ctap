package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.CtapResponseData
import kotlinx.coroutines.Deferred

class Transaction<TR : CtapResponse<TRD>?, TRD : CtapResponseData>(private val deferred: Deferred<TR>) :
    Deferred<TR> by deferred