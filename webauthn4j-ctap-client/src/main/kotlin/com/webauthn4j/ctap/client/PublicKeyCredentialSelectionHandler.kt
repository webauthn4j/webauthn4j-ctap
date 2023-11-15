package com.webauthn4j.ctap.client

import com.webauthn4j.data.AuthenticatorAssertionResponse
import com.webauthn4j.data.PublicKeyCredential
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput

fun interface PublicKeyCredentialSelectionHandler {
    fun select(list: List<GetAssertionsResponse.Assertion>): GetAssertionsResponse.Assertion
}
