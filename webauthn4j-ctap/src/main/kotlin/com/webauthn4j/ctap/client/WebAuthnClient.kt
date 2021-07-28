package com.webauthn4j.ctap.client

import com.webauthn4j.converter.AttestationObjectConverter
import com.webauthn4j.converter.CollectedClientDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.*
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput

@Suppress("CanBePrimaryConstructorProperty")
class WebAuthnClient(
    ctapAuthenticatorHandles: List<CtapAuthenticatorHandle> = listOf(),
    objectConverter: ObjectConverter = ObjectConverter()
) {

    val ctapAuthenticatorHandles: List<CtapAuthenticatorHandle> = ctapAuthenticatorHandles
    val collectedClientDataConverter: CollectedClientDataConverter =
        CollectedClientDataConverter(objectConverter)
    val attestationObjectConverter: AttestationObjectConverter =
        AttestationObjectConverter(objectConverter)
    var clientPINProvider: ClientPINProvider? = null
    var ctapAuthenticatorSelectionHandler: CtapAuthenticatorSelectionHandler =
        DefaultCtapAuthenticatorSelectionHandler()
    var publicKeyCredentialSelectionHandler: PublicKeyCredentialSelectionHandler =
        DefaultPublicKeyCredentialSelectionHandler()

    suspend fun create(
        publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
        clientProperty: ClientProperty
    ): PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> {
        return CreateOperation(this, publicKeyCredentialCreationOptions, clientProperty).execute()
    }

    suspend fun get(
        publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions,
        clientProperty: ClientProperty
    ): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
        return GetOperation(this, publicKeyCredentialRequestOptions, clientProperty).execute()
    }

    private inner class DefaultPublicKeyCredentialSelectionHandler :
        PublicKeyCredentialSelectionHandler {
        override fun select(list: List<PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>>): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
            return list.first()
        }
    }

    private inner class DefaultCtapAuthenticatorSelectionHandler :
        CtapAuthenticatorSelectionHandler {


        override fun select(list: List<CtapAuthenticatorHandle>): CtapAuthenticatorHandle {
            return list.first()
        }
    }

}