package com.webauthn4j.ctap.client

import com.webauthn4j.converter.AttestationObjectConverter
import com.webauthn4j.converter.CollectedClientDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.PlatformOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.client.ClientDataType
import com.webauthn4j.data.client.CollectedClientData
import com.webauthn4j.data.client.TokenBinding
import com.webauthn4j.data.client.TokenBindingStatus
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput
import com.webauthn4j.util.MessageDigestUtil

/**
 * WebAuthn Client
 */
@Suppress("CanBePrimaryConstructorProperty")
class WebAuthnClient(
    ctapClients: List<CtapClient> = listOf(),
    objectConverter: ObjectConverter = ObjectConverter()
) {

    private val ctapClients: List<CtapClient> = ctapClients
    private val collectedClientDataConverter: CollectedClientDataConverter = CollectedClientDataConverter(objectConverter)
    private val attestationObjectConverter: AttestationObjectConverter = AttestationObjectConverter(objectConverter)

    suspend fun create(
        publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
        publicKeyCredentialCreationContext: PublicKeyCredentialCreationContext
    ): PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> {

        val filteredCtapClients = ctapClients.filter { isCreateOperationTargetCtapClient(publicKeyCredentialCreationOptions, it) }
        if (filteredCtapClients.isEmpty()) {
            throw WebAuthnClientException("Matching authenticator doesn't exist.")
        }
        val ctapClient = publicKeyCredentialCreationContext.ctapAuthenticatorSelectionHandler.select(filteredCtapClients)

        // makeCredential
        val collectedClientData = CollectedClientData(
            ClientDataType.WEBAUTHN_CREATE,
            publicKeyCredentialCreationOptions.challenge,
            publicKeyCredentialCreationContext.origin,
            TokenBinding(TokenBindingStatus.NOT_SUPPORTED, null as ByteArray?)
        )
        val clientDataJSON = collectedClientDataConverter.convertToBytes(collectedClientData)
        val clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSON)
        val rpId = publicKeyCredentialCreationOptions.rp.id ?: publicKeyCredentialCreationContext.origin.host
        ?: throw WebAuthnClientException("WebAuthn client must have origin.")
        val rp =
            CtapPublicKeyCredentialRpEntity(rpId, publicKeyCredentialCreationOptions.rp.name, null)
        val user = CtapPublicKeyCredentialUserEntity(
            publicKeyCredentialCreationOptions.user.id,
            publicKeyCredentialCreationOptions.user.name,
            publicKeyCredentialCreationOptions.user.displayName,
            null
        )
        val authenticatorExtensions: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>? =
            null //TODO: implement extension handling
        val makeCredentialRequest =
            MakeCredentialRequest(
                clientDataHash,
                rp,
                user,
                publicKeyCredentialCreationOptions.pubKeyCredParams,
                publicKeyCredentialCreationOptions.excludeCredentials,
                authenticatorExtensions,
                publicKeyCredentialCreationOptions.authenticatorSelection,
                publicKeyCredentialCreationOptions.timeout?.toULong(),
            )
        val makeCredentialContext =
            MakeCredentialContext(
                publicKeyCredentialCreationContext.clientPINProvider::provide,
                object : AuthenticatorUserVerificationHandler {
                    override suspend fun onAuthenticatorUserVerificationStarted() {
                        //nop
                    }

                    override suspend fun onAuthenticatorUserVerificationFinished() {
                        //nop
                    }
                }
            )
        val ctapService = CtapService(ctapClient)
        val makeCredentialResponse: MakeCredentialResponse = ctapService.makeCredential(makeCredentialRequest, makeCredentialContext)
        val credentialId =
            makeCredentialResponse.authenticatorData.attestedCredentialData!!.credentialId
        val attestationObject = when (publicKeyCredentialCreationOptions.attestation) {
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
                    publicKeyCredentialCreationOptions.attestation
                )
            )
        }
        val attestationObjectBytes = attestationObjectConverter.convertToBytes(attestationObject)
        val transports: Set<AuthenticatorTransport> = setOf(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID) //TODO: take appropriate value from somewhere
        val authenticatorAttestationResponse =
            AuthenticatorAttestationResponse(clientDataJSON, attestationObjectBytes, transports)
        return PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>(
            credentialId,
            authenticatorAttestationResponse,
            AuthenticatorAttachment.PLATFORM, //TODO: take appropriate value from somewhere
            AuthenticationExtensionsClientOutputs() //TODO: implement extension handling
        )
    }

    suspend fun get(
        publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions,
        publicKeyCredentialRequestContext: PublicKeyCredentialRequestContext
    ): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
        val filteredCtapClients = ctapClients.filter { isGetOperationTargetCtapClient(publicKeyCredentialRequestOptions, it) }
        if (filteredCtapClients.isEmpty()) {
            throw WebAuthnClientException("Matching authenticator doesn't exist.")
        }
        val ctapClient = publicKeyCredentialRequestContext.ctapAuthenticatorSelectionHandler.select(filteredCtapClients)

        // prepare getAssertionRequest
        val collectedClientData = CollectedClientData(
            ClientDataType.WEBAUTHN_GET,
            publicKeyCredentialRequestOptions.challenge,
            publicKeyCredentialRequestContext.origin,
            TokenBinding(TokenBindingStatus.NOT_SUPPORTED, null as ByteArray?)
        )
        val clientDataJSON = collectedClientDataConverter.convertToBytes(collectedClientData)
        val clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSON)
        val authenticatorExtensions: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>? = null //TODO: implement extension handling
        val rpId = publicKeyCredentialRequestOptions.rpId ?: publicKeyCredentialRequestContext.origin.host ?: throw WebAuthnClientException("WebAuthn client must have origin.")
        val getAssertionsRequest = GetAssertionsRequest(
            rpId,
            clientDataHash,
            publicKeyCredentialRequestOptions.allowCredentials,
            authenticatorExtensions,
            publicKeyCredentialRequestOptions.userVerification,
            publicKeyCredentialRequestOptions.timeout?.toULong()
        )

        val getAssertionsContext = GetAssertionContext(publicKeyCredentialRequestContext.clientPINProvider::provide)

        val ctapService = CtapService(ctapClient)

        val getAssertionsResponse: GetAssertionsResponse = ctapService.getAssertions(getAssertionsRequest, getAssertionsContext)

        val assertion = publicKeyCredentialRequestContext.publicKeyCredentialSelectionHandler.select(getAssertionsResponse.assertions)

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

    private suspend fun isGetOperationTargetCtapClient(publicKeyCredentialRequestOptions : PublicKeyCredentialRequestOptions, ctapClient: CtapClient): Boolean {
        val getInfoResponseData = ctapClient.getInfo().responseData
        return checkUserVerificationCriteria(
            publicKeyCredentialRequestOptions.userVerification,
            getInfoResponseData?.options?.uv,
            getInfoResponseData?.options?.clientPin
        )
    }
    private suspend fun isCreateOperationTargetCtapClient(publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions, ctapClient: CtapClient): Boolean {
        val authenticatorSelectionCriteria = publicKeyCredentialCreationOptions.authenticatorSelection
        val responseData = ctapClient.getInfo().responseData
        return checkAuthenticatorAttachmentCriteria(authenticatorSelectionCriteria?.authenticatorAttachment, responseData?.options?.plat) &&
                checkResidentKeyCriteria(authenticatorSelectionCriteria?.isRequireResidentKey, authenticatorSelectionCriteria?.residentKey, responseData?.options?.rk) &&
                checkUserVerificationCriteria(authenticatorSelectionCriteria?.userVerification, responseData?.options?.uv, responseData?.options?.clientPin)
    }
    protected fun checkAuthenticatorAttachmentCriteria(
        authenticatorAttachment: AuthenticatorAttachment?,
        platformOption: PlatformOption?
    ): Boolean {
        return when (authenticatorAttachment) {
            AuthenticatorAttachment.PLATFORM -> when (platformOption) {
                PlatformOption.PLATFORM -> true
                PlatformOption.CROSS_PLATFORM -> false
                PlatformOption.NULL -> true
                else -> false
            }
            AuthenticatorAttachment.CROSS_PLATFORM -> {
                when (platformOption) {
                    PlatformOption.PLATFORM -> false
                    PlatformOption.CROSS_PLATFORM -> true
                    PlatformOption.NULL -> true
                    else -> false
                }
            }
            null -> true
            else -> throw java.lang.IllegalStateException("unexpected authenticatorAttachment.")
        }

    }

    protected fun checkResidentKeyCriteria(
        requireResidentKey: Boolean?,
        residentKey: ResidentKeyRequirement?,
        residentKeyOption: ResidentKeyOption?
    ): Boolean {
        return when (residentKey) {
            null -> {
                when (requireResidentKey) {
                    true -> residentKeyOption == ResidentKeyOption.SUPPORTED
                    false -> true
                    else -> true
                }
            }
            ResidentKeyRequirement.REQUIRED -> {
                residentKeyOption == ResidentKeyOption.SUPPORTED
            }
            ResidentKeyRequirement.PREFERRED -> {
                true
            }
            ResidentKeyRequirement.DISCOURAGED -> {
                true
            }
            else -> throw NotImplementedError("unknown option")
        }
    }

    protected fun checkUserVerificationCriteria(
        userVerification: UserVerificationRequirement?,
        uv: UserVerificationOption?,
        clientPin: ClientPINOption?
    ): Boolean {
        return when (userVerification) {
            UserVerificationRequirement.REQUIRED -> uv == UserVerificationOption.READY || clientPin == ClientPINOption.SET
            UserVerificationRequirement.PREFERRED, UserVerificationRequirement.DISCOURAGED -> true
            else -> throw IllegalStateException("Unexpected userVerification requirement.")
        }
    }
}