package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.client.ClientDataType
import com.webauthn4j.data.client.CollectedClientData
import com.webauthn4j.data.client.TokenBinding
import com.webauthn4j.data.client.TokenBindingStatus
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput
import com.webauthn4j.util.MessageDigestUtil

class CreateOperation(
    webAuthnClient: WebAuthnClient,
    private val publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
    private val clientProperty: ClientProperty
) : WebAuthnOperationBase(webAuthnClient) {

    suspend fun execute(): PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> {
        val ctapClients = webAuthnClient.ctapAuthenticatorHandles.filter { match(it) }
        if (ctapClients.isEmpty()) {
            throw WebAuthnClientException("Matching authenticator doesn't exist.")
        }
        val ctapClient = webAuthnClient.ctapAuthenticatorSelectionHandler.select(ctapClients)
        return makeCredential(ctapClient)
    }

    private suspend fun match(ctapAuthenticatorHandle: CtapAuthenticatorHandle): Boolean {
        val criteria = publicKeyCredentialCreationOptions.authenticatorSelection
        val responseData = ctapAuthenticatorHandle.getInfo().responseData
        return matchByAuthenticatorAttachment(
            criteria?.authenticatorAttachment,
            responseData?.options?.plat
        ) &&
                matchByResidentKey(
                    criteria?.isRequireResidentKey,
                    criteria?.residentKey,
                    responseData?.options?.rk
                ) &&
                matchByUserVerification(
                    criteria?.userVerification,
                    responseData?.options?.uv,
                    responseData?.options?.clientPin
                )
    }


    private suspend fun makeCredential(ctapAuthenticatorHandle: CtapAuthenticatorHandle): PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> {
        // makeCredential
        val collectedClientData = CollectedClientData(
            ClientDataType.CREATE,
            publicKeyCredentialCreationOptions.challenge,
            clientProperty.origin,
            TokenBinding(TokenBindingStatus.NOT_SUPPORTED, null as ByteArray?)
        )
        val clientDataJSON =
            webAuthnClient.collectedClientDataConverter.convertToBytes(collectedClientData)
        val clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSON)
        val rpId = publicKeyCredentialCreationOptions.rp.id ?: clientProperty.origin.host
        ?: throw WebAuthnClientException("WebAuthn client must have origin.")
        val rp = CtapPublicKeyCredentialRpEntity(rpId, publicKeyCredentialCreationOptions.rp.name)
        val user = CtapPublicKeyCredentialUserEntity(publicKeyCredentialCreationOptions.user.id, publicKeyCredentialCreationOptions.user.name, publicKeyCredentialCreationOptions.user.displayName)
        val authenticatorExtensions: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>? =
            null //TODO
        val makeCredentialRequest = MakeCredentialRequest(
            clientDataHash,
            rp,
            user,
            publicKeyCredentialCreationOptions.pubKeyCredParams,
            publicKeyCredentialCreationOptions.excludeCredentials,
            authenticatorExtensions,
            publicKeyCredentialCreationOptions.authenticatorSelection,
            publicKeyCredentialCreationOptions.timeout,
            object : ClientPINUserVerificationHandler {
                override suspend fun onClientPINRequested(): String {
                    return clientProperty.clientPIN
                }
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
        val makeCredentialResponse: MakeCredentialResponse =
            ctapService.makeCredential(makeCredentialRequest)
        val credentialId =
            makeCredentialResponse.authenticatorData.attestedCredentialData!!.credentialId
        val attestationObject = when (publicKeyCredentialCreationOptions.attestation) {
            AttestationConveyancePreference.NONE -> AttestationObject(
                makeCredentialResponse.attestationObject.authenticatorData,
                NoneAttestationStatement()
            )
            AttestationConveyancePreference.INDIRECT -> TODO("not implemented")
            AttestationConveyancePreference.DIRECT -> makeCredentialResponse.attestationObject
            AttestationConveyancePreference.ENTERPRISE -> makeCredentialResponse.attestationObject //TODO: revisit
            else -> throw IllegalStateException(
                String.format(
                    "AttestationConveyancePreference {} ist not supported",
                    publicKeyCredentialCreationOptions.attestation
                )
            )
        }
        val attestationObjectBytes =
            webAuthnClient.attestationObjectConverter.convertToBytes(attestationObject)
        val authenticatorAttestationResponse =
            AuthenticatorAttestationResponse(clientDataJSON, attestationObjectBytes)
        return PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>(
            credentialId,
            authenticatorAttestationResponse,
            null
        )
    }
}