package com.webauthn4j.ctap.client

import com.webauthn4j.data.AuthenticatorAssertionResponse
import com.webauthn4j.data.PublicKeyCredential
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput

interface PublicKeyCredentialSelectionHandler {
    fun select(list: List<PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>>): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>
}
