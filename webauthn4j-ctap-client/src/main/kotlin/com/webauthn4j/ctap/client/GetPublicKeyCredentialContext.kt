package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.client.exception.CtapClientException
import com.webauthn4j.data.AuthenticatorAssertionResponse
import com.webauthn4j.data.PublicKeyCredential
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput

class GetPublicKeyCredentialContext @JvmOverloads constructor(
    val origin: Origin,
    var ctapAuthenticatorSelectionHandler: CtapAuthenticatorSelectionHandler = DefaultCtapAuthenticatorSelectionHandler(),
    var publicKeyCredentialSelectionHandler: PublicKeyCredentialSelectionHandler = DefaultPublicKeyCredentialSelectionHandler(),
    var clientPINProvider: ClientPINProvider = NoClientPINProvider()
){

    private class DefaultCtapAuthenticatorSelectionHandler : CtapAuthenticatorSelectionHandler {
        override fun select(list: List<CtapAuthenticatorHandle>): CtapAuthenticatorHandle {
            return list.first()
        }
    }

    private class DefaultPublicKeyCredentialSelectionHandler : PublicKeyCredentialSelectionHandler {
        override fun select(list: List<GetAssertionsResponse.Assertion>): GetAssertionsResponse.Assertion {
            return list.first()
        }
    }
    private class NoClientPINProvider : ClientPINProvider {
        override suspend fun provide(): ByteArray {
            throw CtapClientException("ClientPINProvider is not configured")
        }
    }
}
