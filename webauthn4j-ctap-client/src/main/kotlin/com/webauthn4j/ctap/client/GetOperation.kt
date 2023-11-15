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
    private val getPublicKeyCredentialContext: GetPublicKeyCredentialContext
) : WebAuthnOperationBase(webAuthnClient) {

    suspend fun execute(): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
        val ctapClients = webAuthnClient.ctapAuthenticatorHandles.filter { match(it) }
        if (ctapClients.isEmpty()) {
            throw WebAuthnClientException("Matching authenticator doesn't exist.")
        }
        val ctapClient = getPublicKeyCredentialContext.ctapAuthenticatorSelectionHandler.select(ctapClients)
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
            ClientDataType.WEBAUTHN_GET,
            publicKeyCredentialRequestOptions.challenge,
            getPublicKeyCredentialContext.origin,
            TokenBinding(TokenBindingStatus.NOT_SUPPORTED, null as ByteArray?)
        )
        val clientDataJSON =
            webAuthnClient.collectedClientDataConverter.convertToBytes(collectedClientData)
        val clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSON)
        val authenticatorExtensions: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>? = null //TODO: implement extension handling
        val rpId = publicKeyCredentialRequestOptions.rpId ?: getPublicKeyCredentialContext.origin.host ?: throw WebAuthnClientException("WebAuthn client must have origin.")
        val getAssertionsRequest = GetAssertionsRequest(
            rpId,
            clientDataHash,
            publicKeyCredentialRequestOptions.allowCredentials,
            authenticatorExtensions,
            publicKeyCredentialRequestOptions.userVerification,
            publicKeyCredentialRequestOptions.timeout?.toULong(),
            { getPublicKeyCredentialContext.clientPINProvider.provide() },
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
        val getAssertionsResponse: GetAssertionsResponse = ctapService.getAssertions(getAssertionsRequest)

        val assertion = getPublicKeyCredentialContext.publicKeyCredentialSelectionHandler.select(getAssertionsResponse.assertions)

        val credentialId = assertion.credential?.id
        val authenticatorData = assertion.authData
        val signature = assertion.signature
        val userHandle = assertion.user?.id
        val clientExtensionResults: AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput>? = null //TODO: implement extension handling
        return PublicKeyCredential(
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
}