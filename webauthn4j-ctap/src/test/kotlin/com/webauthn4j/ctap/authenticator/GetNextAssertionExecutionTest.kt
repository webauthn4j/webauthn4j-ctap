package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import java.time.Instant

@ExperimentalCoroutinesApi
class GetNextAssertionExecutionTest {

    @Test
    fun createErrorResponse_test() {
        val response = GetNextAssertionExecution(
            Mockito.mock(CtapAuthenticator::class.java),
            Mockito.mock(AuthenticatorGetNextAssertionRequest::class.java)
        ).createErrorResponse(CtapStatusCode.CTAP1_ERR_OTHER)
        Assertions.assertThat(response)
            .isInstanceOf(AuthenticatorGetNextAssertionResponse::class.java)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP1_ERR_OTHER)
    }

    @Test
    fun getNextAssertion_test() = runBlockingTest {
        val ctapAuthenticator =
            CtapAuthenticator(settings = CtapAuthenticatorSettings(credentialSelector = CredentialSelectorSetting.CLIENT_PLATFORM))
        makeCredential(ctapAuthenticator)
        makeCredential(ctapAuthenticator)

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = true)
        val pinAuth: ByteArray? = null
        val pinProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            options,
            pinAuth,
            pinProtocol
        )
        ctapAuthenticator.getAssertion(command)
        val response = ctapAuthenticator.getNextAssertion()
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
    }

    @Test
    fun getNextAssertion_when_no_session_exist_test() = runBlockingTest {
        val ctapAuthenticator =
            CtapAuthenticator(settings = CtapAuthenticatorSettings(credentialSelector = CredentialSelectorSetting.CLIENT_PLATFORM))
        makeCredential(ctapAuthenticator)

        val response = ctapAuthenticator.getNextAssertion(AuthenticatorGetNextAssertionRequest())
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
    }

    @Test
    fun getNextAssertion_when_next_credential_does_not_exist_test() = runBlockingTest {
        val ctapAuthenticator =
            CtapAuthenticator(settings = CtapAuthenticatorSettings(credentialSelector = CredentialSelectorSetting.CLIENT_PLATFORM))
        makeCredential(ctapAuthenticator)
        makeCredential(ctapAuthenticator)

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = true)
        val pinAuth: ByteArray? = null
        val pinProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            options,
            pinAuth,
            pinProtocol
        )
        ctapAuthenticator.getAssertion(command) // fetch 1st credential
        ctapAuthenticator.getNextAssertion(AuthenticatorGetNextAssertionRequest()) // fetch 2nd credential
        val response =
            ctapAuthenticator.getNextAssertion(AuthenticatorGetNextAssertionRequest()) // return error as 3rd credential doesn't exist
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
    }

    @Test
    fun expiration_test() = runBlockingTest {
        val ctapAuthenticator =
            CtapAuthenticator(settings = CtapAuthenticatorSettings(credentialSelector = CredentialSelectorSetting.CLIENT_PLATFORM))
        makeCredential(ctapAuthenticator)
        makeCredential(ctapAuthenticator)

        val instant = Instant.parse("2020-01-01T00:00:00Z")
        val expiredInstant = Instant.parse("2020-01-01T00:00:30Z")
        Mockito.mockStatic(Instant::class.java).use {


            val clientDataHash = ByteArray(0)
            val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
            val extensions =
                AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
            val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = true)
            val pinAuth: ByteArray? = null
            val pinProtocol: PinProtocolVersion? = null
            val command = AuthenticatorGetAssertionRequest(
                "example.com",
                clientDataHash,
                allowList,
                extensions,
                options,
                pinAuth,
                pinProtocol
            )

            it.`when`<Instant>(Instant::now)
                .thenReturn(instant) // override current time to fixed time
            ctapAuthenticator.getAssertion(command)
        }

        Mockito.mockStatic(Instant::class.java).use {
            it.`when`<Instant>(Instant::now)
                .thenReturn(expiredInstant) // override current time to fixed time (expired)
            val response =
                ctapAuthenticator.getNextAssertion(AuthenticatorGetNextAssertionRequest())
            Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        }
    }


    @Test
    suspend fun makeCredential(
        ctapAuthenticator: CtapAuthenticator,
        rk: Boolean = true,
        uv: Boolean = true
    ) {
        val clientDataHash = ByteArray(0)
        val rp = CtapPublicKeyCredentialRpEntity("example.com", "example", "rpIcon")
        val user = CtapPublicKeyCredentialUserEntity(byteArrayOf(0x01, 0x23), "John.doe", "John Doe", "icon")
        val pubKeyCredParams = listOf(
            PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.ES256
            )
        )
        val excludeList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>()
        val options = AuthenticatorMakeCredentialRequest.Options(rk = rk, uv = uv)
        val pinAuth: ByteArray? = null
        val pinProtocol: PinProtocolVersion? = null
        val command = AuthenticatorMakeCredentialRequest(
            clientDataHash,
            rp,
            user,
            pubKeyCredParams,
            excludeList,
            extensions,
            options,
            pinAuth,
            pinProtocol
        )
        val response = ctapAuthenticator.makeCredential(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
        Assertions.assertThat(response.responseData!!.attestationStatement).isNotNull
        Assertions.assertThat(response.responseData!!.authenticatorData).isNotNull
    }
}