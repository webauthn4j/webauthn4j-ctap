package com.unifidokey.driver.credentials.provider

import com.unifidokey.core.config.ConfigManager
import com.webauthn4j.converter.AttestationObjectConverter
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.client.CtapClient
import com.webauthn4j.ctap.client.CtapService
import com.webauthn4j.ctap.client.GetAssertionContext
import com.webauthn4j.ctap.client.GetAssertionsRequest
import com.webauthn4j.ctap.client.MakeCredentialContext
import com.webauthn4j.ctap.client.MakeCredentialRequest
import com.webauthn4j.ctap.client.MakeCredentialResponse
import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import com.webauthn4j.ctap.client.transport.InProcessTransportAdaptor
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.AuthenticatorAttachment
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.client.ClientDataType
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.util.MessageDigestUtil

class AndroidCredentialsAuthenticator(
    private val configManager: ConfigManager,
    private val ctapAuthenticator: CtapAuthenticator) {
    private val objectConverter = ctapAuthenticator.objectConverter
    private val attestationObjectConverter = AttestationObjectConverter(ctapAuthenticator.objectConverter)

    private val ctapService: CtapService
        get() {
            val connection = ctapAuthenticator.createSession()
            val ctapClient = CtapClient(InProcessTransportAdaptor(connection))
            return CtapService(ctapClient)
        }

    suspend fun create(credentialCreateRequest: AndroidCredentialsCreateRequest, credentialCreateContext: AndroidCredentialsCreateContext): AndroidCredentialsCreateResponse {

        // makeCredential
        val collectedClientData = AndroidClientData(
            ClientDataType.WEBAUTHN_CREATE,
            credentialCreateRequest.challenge,
            credentialCreateContext.origin,
            credentialCreateContext.packageName
        )

        val clientDataJSON = objectConverter.jsonConverter.writeValueAsBytes(collectedClientData)
        val clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSON)
        val rpId = credentialCreateRequest.rp.id ?: credentialCreateContext.origin.host ?: throw WebAuthnClientException("WebAuthn client must have origin.")
        val rp = CtapPublicKeyCredentialRpEntity(rpId, credentialCreateRequest.rp.name, null)
        val user = CtapPublicKeyCredentialUserEntity(
            credentialCreateRequest.user.id,
            credentialCreateRequest.user.name,
            credentialCreateRequest.user.displayName,
            null
        )
        val authenticatorExtensions: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>? = null //TODO: implement extension handling
        val makeCredentialRequest =
            MakeCredentialRequest(
                clientDataHash,
                rp,
                user,
                credentialCreateRequest.pubKeyCredParams,
                credentialCreateRequest.excludeCredentials,
                authenticatorExtensions,
                credentialCreateRequest.authenticatorSelection,
                credentialCreateRequest.timeout?.toULong(),
            )
        val makeCredentialContext = MakeCredentialContext(clientPINRequestHandler = { throw IllegalStateException("clientPIN request is not expected.") })
        val makeCredentialResponse: MakeCredentialResponse = ctapService.makeCredential(makeCredentialRequest, makeCredentialContext)
        val credentialId =
            makeCredentialResponse.authenticatorData.attestedCredentialData!!.credentialId
        val attestationObject = when (credentialCreateRequest.attestation) {
            AttestationConveyancePreference.NONE -> AttestationObject(
                makeCredentialResponse.attestationObject.authenticatorData,
                NoneAttestationStatement()
            )
            AttestationConveyancePreference.INDIRECT -> makeCredentialResponse.attestationObject //TODO: implement replacing the attestation with anonymous but verifiable one
            AttestationConveyancePreference.DIRECT -> makeCredentialResponse.attestationObject
            AttestationConveyancePreference.ENTERPRISE -> makeCredentialResponse.attestationObject //TODO: implement enterprise attestation
            else -> throw IllegalStateException(
                String.format(
                    "AttestationConveyancePreference {} ist not supported",
                    credentialCreateRequest.attestation
                )
            )
        }
        val attestationObjectBytes = attestationObjectConverter.convertToBytes(attestationObject)
        val transports: Set<AuthenticatorTransport> = setOf(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID) //TODO: take appropriate value from somewhere
        val authenticatorAttestationResponse =
            AndroidCredentialsCreateResponse.AuthenticatorAttestationResponse(
                clientDataJSON,
                attestationObjectBytes,
                transports
            )
        return AndroidCredentialsCreateResponse(
            credentialId,
            authenticatorAttestationResponse,
            AuthenticatorAttachment.PLATFORM, //TODO: take appropriate value from somewhere
            AuthenticationExtensionsClientOutputs() //TODO: implement extension handling
        )
    }

    suspend fun get(credentialGetRequest: AndroidCredentialsGetRequest, credentialGetContext: AndroidCredentialsGetContext): AndroidCredentialsGetResponse {
        //TODO ctapAuthenticator.credentialSelectorSetting should be PLATFORM

        // prepare getAssertionRequest
        val rpId = credentialGetRequest.rpId ?: credentialGetContext.origin.host ?: throw WebAuthnClientException("WebAuthn client must have origin.")

        val getAssertionsRequest = GetAssertionsRequest(
            rpId,
            credentialGetContext.clientDataHash,
            credentialGetRequest.allowCredentials,
            null,
            credentialGetRequest.userVerification,
            ULong.MAX_VALUE //TODO
        )
        val getAssertionsContext = GetAssertionContext( clientPINRequestHandler = { throw IllegalStateException("clientPIN request is not expected.") })
        val getAssertionsResponse = ctapService.getAssertions(getAssertionsRequest, getAssertionsContext)
        val assertion = getAssertionsResponse.assertions.first()
        val credentialId = assertion.credential?.id!!
        val authenticatorData = assertion.authData
        val signature = assertion.signature
        val userHandle = assertion.user?.id!!
        val clientExtensionResults: AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> = AuthenticationExtensionsClientOutputs() //TODO: implement extension handling
        return AndroidCredentialsGetResponse(
            credentialId,
            AndroidCredentialsGetResponse.AuthenticatorAssertionResponse(
                authenticatorData,
                signature,
                userHandle
            ),
            AuthenticatorAttachment.PLATFORM, //TODO: take appropriate value from somewhere
            clientExtensionResults,
        )
    }

}