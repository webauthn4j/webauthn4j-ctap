package com.webauthn4j.ctap.core.data

class AuthenticatorGetNextAssertionRequest : CtapRequest {

    override val command: CtapCommand = CtapCommand.GET_NEXT_ASSERTION

    override fun toString(): String {
        return "AuthenticatorGetNextAssertionCommand()"
    }
}