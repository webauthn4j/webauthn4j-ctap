package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.AuthenticatorResponse
import kotlinx.coroutines.Deferred

class Transaction<TR : AuthenticatorResponse>(private val deferred: Deferred<TR>) :
    Deferred<TR> by deferred