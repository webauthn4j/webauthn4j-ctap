package com.webauthn4j.ctap.core.data

class AuthenticatorResetRequest : CtapRequest {

    override val command: CtapCommand = CtapCommand.RESET

    override fun toString(): String {
        return "AuthenticatorResetCommand()"
    }
}
