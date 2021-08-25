package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import com.webauthn4j.data.AuthenticatorAssertionResponse
import com.webauthn4j.data.PublicKeyCredential
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.client.ClientDataType
import com.webauthn4j.data.client.CollectedClientData
import com.webauthn4j.data.client.TokenBinding
import com.webauthn4j.data.client.TokenBindingStatus
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.util.MessageDigestUtil

class GetOperation(
    webAuthnClient: WebAuthnClient,
    private val publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions,
    private val clientProperty: ClientProperty
) : WebAuthnOperationBase(webAuthnClient) {

    suspend fun execute(): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
        val ctapClients = webAuthnClient.ctapAuthenticatorHandles.filter { match(it) }
        if (ctapClients.isEmpty()) {
            throw WebAuthnClientException("Matching authenticator doesn't exist.")
        }
        val ctapClient = webAuthnClient.ctapAuthenticatorSelectionHandler.select(ctapClients)
        return getAssertions(ctapClient)
    }

    private suspend fun match(ctapAuthenticatorHandle: CtapAuthenticatorHandle): Boolean {
        val getInfoResponseData = ctapAuthenticatorHandle.getInfo().responseData
        return matchByUserVerification(
            publicKeyCredentialRequestOptions.userVerification,
            getInfoResponseData?.options?.uv,
            getInfoResponseData?.options?.clientPin
        )
    }

    private suspend fun getAssertions(ctapAuthenticatorHandle: CtapAuthenticatorHandle): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
        val collectedClientData = CollectedClientData(
            ClientDataType.GET,
            publicKeyCredentialRequestOptions.challenge,
            clientProperty.origin,
            TokenBinding(TokenBindingStatus.NOT_SUPPORTED, null as ByteArray?)
        )
        val clientDataJSON =
            webAuthnClient.collectedClientDataConverter.convertToBytes(collectedClientData)
        val clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSON)
        val authenticatorExtensions: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>? =
            null //TODO
        val rpId = publicKeyCredentialRequestOptions.rpId ?: clientProperty.origin.host
        ?: throw WebAuthnClientException("WebAuthn client must have origin.")
        val getAssertionsRequest = GetAssertionsRequest(
            rpId,
            clientDataHash,
            publicKeyCredentialRequestOptions.allowCredentials,
            authenticatorExtensions,
            publicKeyCredentialRequestOptions.userVerification,
            publicKeyCredentialRequestOptions.timeout,
            object : ClientPINUserVerificationHandler {
                override suspend fun onClientPINRequested(): String = clientProperty.clientPIN
            },
            object : AuthenticatorUserVerificationHandler {
                override suspend fun onAuthenticatorUserVerificationStarted() {
                    //nop
                }

                override suspend fun onAuthenticatorUserVerificationFinished() {
                    //nop
                }
            }
        )
        val ctapService = CtapClient(ctapAuthenticatorHandle)
        val getAssertionsResponse: GetAssertionsResponse =
            ctapService.getAssertions(getAssertionsRequest)
        val publicKeyCredentials = getAssertionsResponse.assertions.map {
            val credentialId = it.credential?.id
            val authenticatorData = it.authData
            val signature = it.signature
            val userHandle = it.user?.id
            val clientExtensionResults: AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput>? =
                null //TODO
            PublicKeyCredential(
                credentialId,
                AuthenticatorAssertionResponse(
                    clientDataJSON,
                    authenticatorData,
                    signature,
                    userHandle
                ),
                clientExtensionResults
            )
        }
        return webAuthnClient.publicKeyCredentialSelectionHandler.select(publicKeyCredentials)
    }
}