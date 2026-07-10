package com.webauthn4j.ctap.core.data

class AuthenticatorSelectionRequest : CtapRequest {

    override val command: CtapCommand = CtapCommand.SELECTION

    override fun toString(): String {
        return "AuthenticatorSelectionRequest()"
    }
}
