package com.unifidokey.driver.credentials.provider

import androidx.fragment.app.FragmentActivity
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.handler.SettingBasedUserVerificationHandler
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.webauthn4j.converter.AttestationObjectConverter
import com.webauthn4j.ctap.authenticator.CachingUserVerificationHandler
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.client.CtapClient
import com.webauthn4j.ctap.client.CtapService
import com.webauthn4j.ctap.client.GetAssertionContext
import com.webauthn4j.ctap.client.GetAssertionsRequest
import com.webauthn4j.ctap.client.MakeCredentialContext
import com.webauthn4j.ctap.client.MakeCredentialRequest
import com.webauthn4j.ctap.client.MakeCredentialResponse
import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import com.webauthn4j.ctap.authenticator.transport.internal.InternalTransport
import com.webauthn4j.ctap.client.transport.InProcessAdaptor
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.ctap.core.data.options.PlatformOption
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
    private val ctapAuthenticator: CtapAuthenticator,
    private val activity: FragmentActivity,
    private val configManager: ConfigManager,
    private val relyingPartyDao: RelyingPartyDao
) {
    private val objectConverter = ctapAuthenticator.objectConverter
    private val attestationObjectConverter = AttestationObjectConverter(ctapAuthenticator.objectConverter)

    private val ctapService: CtapService
        get() {
            val userVerificationHandler = CachingUserVerificationHandler(SettingBasedUserVerificationHandler(AndroidCredentialsUserVerificationHandler(activity, configManager, relyingPartyDao), configManager))
            val internalTransport = InternalTransport(ctapAuthenticator, userVerificationHandler)
            val ctapClient = CtapClient(InProcessAdaptor(internalTransport))
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
        val authenticatorExtensions: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> = AuthenticationExtensionsAuthenticatorInputs() //TODO: implement extension handling
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
        val getInfoResponse = ctapService.getInfo()
        val makeCredentialResponse: MakeCredentialResponse = ctapService.makeCredential(makeCredentialRequest, makeCredentialContext)
        val credentialId =
            makeCredentialResponse.authenticatorData.attestedCredentialData?.credentialId ?: TODO()
        val attestationObject = when (credentialCreateRequest.attestation) {
            AttestationConveyancePreference.NONE, null -> AttestationObject(
                makeCredentialResponse.attestationObject.authenticatorData,
                NoneAttestationStatement()
            )
            AttestationConveyancePreference.INDIRECT -> makeCredentialResponse.attestationObject //TODO: implement replacing the attestation with anonymous but verifiable one
            AttestationConveyancePreference.DIRECT -> makeCredentialResponse.attestationObject
            AttestationConveyancePreference.ENTERPRISE -> makeCredentialResponse.attestationObject //TODO: implement enterprise attestation
            else -> throw IllegalStateException(
                String.format(
                    "AttestationConveyancePreference %s is not supported",
                    credentialCreateRequest.attestation
                )
            )
        }
        val attestationObjectBytes = attestationObjectConverter.convertToBytes(attestationObject)
        val transports: Set<AuthenticatorTransport> = getInfoResponse.responseData?.transports?.toSet() ?: setOf(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID) // default is internal and hybrid because this is for android credentials provider
        val attachment = when(getInfoResponse.responseData?.options?.plat){
            PlatformOption.PLATFORM -> AuthenticatorAttachment.PLATFORM
            PlatformOption.CROSS_PLATFORM -> AuthenticatorAttachment.CROSS_PLATFORM
            else -> AuthenticatorAttachment.PLATFORM
        }
        val authenticatorAttestationResponse =
            AndroidCredentialsCreateResponse.AuthenticatorAttestationResponse(
                clientDataJSON,
                attestationObjectBytes,
                transports
            )
        return AndroidCredentialsCreateResponse(
            credentialId,
            authenticatorAttestationResponse,
            attachment,
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
        val getInfoResponse = ctapService.getInfo()
        val getAssertionsResponse = ctapService.getAssertions(getAssertionsRequest, getAssertionsContext)
        val assertion = getAssertionsResponse.assertions.first()
        val credentialId = assertion.credential?.id ?: TODO()
        val clientDataJSON = objectConverter.jsonConverter.writeValueAsBytes("{}") // place holder is required. See https://developer.android.com/training/sign-in/credential-provider#obtain-allowlist
        val authenticatorData = assertion.authData
        val signature = assertion.signature
        val userHandle = assertion.user?.id ?: TODO()
        val attachment = when(getInfoResponse.responseData?.options?.plat){
            PlatformOption.PLATFORM -> AuthenticatorAttachment.PLATFORM
            PlatformOption.CROSS_PLATFORM -> AuthenticatorAttachment.CROSS_PLATFORM
            else -> AuthenticatorAttachment.PLATFORM
        }
        val clientExtensionResults: AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> = AuthenticationExtensionsClientOutputs() //TODO: implement extension handling
        return AndroidCredentialsGetResponse(
            credentialId,
            AndroidCredentialsGetResponse.AuthenticatorAssertionResponse(
                clientDataJSON,
                authenticatorData,
                signature,
                userHandle
            ),
            attachment,
            clientExtensionResults,
        )
    }

}