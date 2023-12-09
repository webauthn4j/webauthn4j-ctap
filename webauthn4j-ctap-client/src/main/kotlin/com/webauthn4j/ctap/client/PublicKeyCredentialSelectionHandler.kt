package com.webauthn4j.ctap.client

fun interface PublicKeyCredentialSelectionHandler {
    fun select(list: List<GetAssertionsResponse.Assertion>): GetAssertionsResponse.Assertion
}
