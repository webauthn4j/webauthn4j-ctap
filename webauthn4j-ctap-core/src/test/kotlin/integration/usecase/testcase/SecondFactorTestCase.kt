package integration.usecase.testcase

import com.webauthn4j.authenticator.AuthenticatorImpl
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.RegistrationRequest
import com.webauthn4j.data.UserVerificationRequirement
import org.junit.jupiter.api.fail

class SecondFactorTestCase : IntegrationTestCaseBase() {

    init {
        relyingParty.registration.frontend.requireResidentKey = false
        relyingParty.registration.frontend.userVerification =
            UserVerificationRequirement.DISCOURAGED
        relyingParty.registration.backend.userVerificationRequired = false
        relyingParty.authentication.frontend.userVerification =
            UserVerificationRequirement.DISCOURAGED
        relyingParty.authentication.backend.userVerificationRequired = false
    }

    suspend fun run() {

        // Create a credential on an authenticator through WebAuthn Client Create API
        val registrationResponse = clientPlatform.webAuthnAPIClient.create(
            relyingParty.registration.frontend.publicKeyCredentialCreationOptions,
            relyingParty.registration.frontend.clientProperty
        )
        val credentialId = registrationResponse.rawId
        val attestationAuthenticatorResponse = registrationResponse.authenticatorResponse
            ?: fail("authenticatorResponse must not be null")

        // Validate the credential on a relying party server
        val registrationRequest = RegistrationRequest(
            attestationAuthenticatorResponse.attestationObject,
            attestationAuthenticatorResponse.clientDataJSON,
            objectConverter.jsonConverter.writeValueAsString(registrationResponse.clientExtensionResults),
            attestationAuthenticatorResponse.transports.map { obj: AuthenticatorTransport -> obj.value }
                .toSet()
        )
        val registrationParameters = RegistrationParameters(
            relyingParty.registration.backend.serverProperty,
            null,
            relyingParty.registration.backend.userVerificationRequired,
            relyingParty.registration.backend.userPresenceRequired
        )
        val registrationData =
            relyingParty.webAuthnManager.validate(registrationRequest, registrationParameters)


        // Get a credential from the authenticator through WebAuthn Client Get API
        relyingParty.authentication.frontend.allowCredentials = listOf(
            PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                credentialId,
                null
            )
        )
        val assertionResponse = clientPlatform.webAuthnAPIClient.get(
            relyingParty.authentication.frontend.publicKeyCredentialRequestOptions,
            relyingParty.authentication.frontend.clientProperty
        )
        val assertionAuthenticatorResponse = assertionResponse.authenticatorResponse
            ?: fail("authenticatorResponse must not be null")

        // Validate the credential on a relying party server
        val authenticationRequest = AuthenticationRequest(
            assertionResponse.rawId,
            relyingParty.registration.frontend.userId,
            assertionAuthenticatorResponse.authenticatorData,
            assertionAuthenticatorResponse.clientDataJSON,
            objectConverter.jsonConverter.writeValueAsString(assertionResponse.clientExtensionResults),
            assertionAuthenticatorResponse.signature
        )
        val attestationObject =
            registrationData.attestationObject ?: fail("attestationObject must not be null")
        val authenticatorImpl = AuthenticatorImpl(
            attestationObject.authenticatorData.attestedCredentialData!!,
            attestationObject.attestationStatement,
            attestationObject.authenticatorData.signCount,
            registrationData.transports
        )
        val authenticationParameters = AuthenticationParameters(
            relyingParty.authentication.backend.serverProperty,
            authenticatorImpl,
            null,
            relyingParty.authentication.backend.userVerificationRequired,
            relyingParty.authentication.backend.userPresenceRequired
        )
        relyingParty.webAuthnManager.validate(authenticationRequest, authenticationParameters)
    }

}