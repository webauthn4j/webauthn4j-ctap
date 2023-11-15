package com.webauthn4j.ctap.client

import com.webauthn4j.converter.AttestationObjectConverter
import com.webauthn4j.converter.CollectedClientDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.*
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput

/**
 * WebAuthn Client
 */
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

    suspend fun create(
        publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
        createPublicKeyCredentialContext: CreatePublicKeyCredentialContext
    ): PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> {
        return CreateOperation(
            this,
            publicKeyCredentialCreationOptions,
            createPublicKeyCredentialContext
        ).execute()
    }

    suspend fun get(
        publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions,
        getPublicKeyCredentialContext: GetPublicKeyCredentialContext
    ): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
        return GetOperation(this, publicKeyCredentialRequestOptions, getPublicKeyCredentialContext).execute()
    }
}