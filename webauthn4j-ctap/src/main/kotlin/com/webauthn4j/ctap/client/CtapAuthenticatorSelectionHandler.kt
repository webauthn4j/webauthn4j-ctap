package com.webauthn4j.ctap.client

interface CtapAuthenticatorSelectionHandler {
    fun select(list: List<CtapAuthenticatorHandle>): CtapAuthenticatorHandle
}