package com.webauthn4j.ctap.client

fun interface CtapAuthenticatorSelectionHandler {
    fun select(list: List<CtapClient>): CtapClient
}