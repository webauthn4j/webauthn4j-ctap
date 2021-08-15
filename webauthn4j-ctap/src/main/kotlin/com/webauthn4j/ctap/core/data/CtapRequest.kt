package com.webauthn4j.ctap.core.data

interface CtapRequest : AuthenticatorRequest{

    val command: CtapCommand
}