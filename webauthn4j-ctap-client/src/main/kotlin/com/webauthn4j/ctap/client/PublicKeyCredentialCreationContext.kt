package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.client.exception.CtapClientException
import com.webauthn4j.data.client.Origin

class PublicKeyCredentialCreationContext @JvmOverloads constructor(
    val origin: Origin,
    var ctapAuthenticatorSelectionHandler: CtapAuthenticatorSelectionHandler = DefaultCtapAuthenticatorSelectionHandler(),
    var clientPINProvider: ClientPINProvider = NoClientPINProvider()
){
    private class DefaultCtapAuthenticatorSelectionHandler : CtapAuthenticatorSelectionHandler {
        override fun select(list: List<CtapClient>): CtapClient {
            return list.first()
        }
    }

    private class NoClientPINProvider : ClientPINProvider {
        override suspend fun provide(): ByteArray {
            throw CtapClientException("ClientPINProvider is not configured")
        }
    }
}