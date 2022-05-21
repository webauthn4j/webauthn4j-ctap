package com.webauthn4j.ctap.core.data

class AuthenticatorGetInfoRequest : CtapRequest {

    override val command: CtapCommand = CtapCommand.GET_INFO

    override fun toString(): String {
        return "AuthenticatorGetInfoCommand()"
    }
}