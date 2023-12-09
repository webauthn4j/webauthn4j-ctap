package integration.usecase.testcase

import com.webauthn4j.authenticator.AuthenticatorImpl
import com.webauthn4j.data.*
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput
import org.junit.jupiter.api.fail

class PasswordlessTestCase : IntegrationTestCaseBase() {
    private var _step1Result: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>? =
        null
    private var _step2Result: RegistrationData? = null
    private var _step3Result: PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>? =
        null
    private var _step4Result: AuthenticationData? = null

    @Suppress("MemberVisibilityCanBePrivate")
    var step1Result: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>
        get() {
            _step1Result.let {
                it ?: fail("step1 haven't executed yet.")
                return it
            }
        }
        private set(value) {
            _step1Result = value
        }
    @Suppress("MemberVisibilityCanBePrivate")
    var step2Result: RegistrationData
        get() {
            _step2Result.let {
                it ?: fail("step2 haven't executed yet.")
                return it
            }
        }
        private set(value) {
            _step2Result = value
        }
    @Suppress("MemberVisibilityCanBePrivate")
    var step3Result: PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>
        get() {
            _step3Result.let {
                it ?: fail("step3 haven't executed yet.")
                return it
            }
        }
        private set(value) {
            _step3Result = value
        }
    @Suppress("MemberVisibilityCanBePrivate")
    var step4Result: AuthenticationData
        get() {
            _step4Result.let {
                it ?: fail("step4 haven't executed yet.")
                return it
            }
        }
        private set(value) {
            _step4Result = value
        }

    init {
        relyingParty.registration.frontend.residentKey = ResidentKeyRequirement.REQUIRED
    }

    suspend fun run() {
        step1_createCredential()
        step2_validateCredentialForRegistration()
        step3_getCredential()
        step4_validateCredentialForAuthentication()
    }

    suspend fun step1_createCredential(): PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> {
        step1Result = clientPlatform.webAuthnAPIClient.create(
            relyingParty.registration.frontend.publicKeyCredentialCreationOptions,
            relyingParty.registration.frontend.publicKeyCredentialCreationContext
        )
        return step1Result
    }

    fun step2_validateCredentialForRegistration(): RegistrationData {
        val registrationRequest = RegistrationRequest(
            step1Result.response!!.attestationObject,
            step1Result.response!!.clientDataJSON,
            objectConverter.jsonConverter.writeValueAsString(step1Result.clientExtensionResults),
            step1Result.response!!.transports.map { obj: AuthenticatorTransport -> obj.value }
                .toSet()
        )
        val registrationParameters = RegistrationParameters(
            relyingParty.registration.backend.serverProperty,
            null,
            relyingParty.registration.backend.userVerificationRequired,
            relyingParty.registration.backend.userPresenceRequired
        )

        // Relying Party Server validates the credential for registration
        step2Result =
            relyingParty.webAuthnManager.validate(registrationRequest, registrationParameters)
        return step2Result
    }

    suspend fun step3_getCredential(): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
        // Client gets the credential
        step3Result = clientPlatform.webAuthnAPIClient.get(
            relyingParty.authentication.frontend.publicKeyCredentialRequestOptions,
            relyingParty.authentication.frontend.publicKeyCredentialRequestContext
        )
        return step3Result
    }

    fun step4_validateCredentialForAuthentication(): AuthenticationData {
        val authenticationRequest = AuthenticationRequest(
            step3Result.rawId,
            relyingParty.registration.frontend.userId,
            step3Result.response!!.authenticatorData,
            step3Result.response!!.clientDataJSON,
            objectConverter.jsonConverter.writeValueAsString(step3Result.clientExtensionResults),
            step3Result.response!!.signature
        )
        val authenticatorImpl = AuthenticatorImpl(
            step2Result.attestationObject!!.authenticatorData.attestedCredentialData!!,
            step2Result.attestationObject!!.attestationStatement,
            step2Result.attestationObject!!.authenticatorData.signCount,
            step2Result.transports
        )
        val authenticationParameters = AuthenticationParameters(
            relyingParty.authentication.backend.serverProperty,
            authenticatorImpl,
            null,
            relyingParty.authentication.backend.userVerificationRequired,
            relyingParty.authentication.backend.userPresenceRequired
        )

        // Relying Party Server validate the credential for registration
        step4Result = relyingParty.webAuthnManager.validate(authenticationRequest, authenticationParameters)
        return step4Result
    }
}