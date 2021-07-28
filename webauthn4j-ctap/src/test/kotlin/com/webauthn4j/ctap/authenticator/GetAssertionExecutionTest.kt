package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.exception.StoreFullException
import com.webauthn4j.ctap.authenticator.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.ResidentUserCredential
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.mockito.Mockito
import java.io.Serializable

@ExperimentalCoroutinesApi
internal class GetAssertionExecutionTest {

    @Test
    fun createErrorResponse_test() {
        val response = GetAssertionExecution(
            Mockito.mock(CtapAuthenticator::class.java),
            Mockito.mock(AuthenticatorGetAssertionRequest::class.java)
        ).createErrorResponse(StatusCode.CTAP1_ERR_OTHER)
        Assertions.assertThat(response).isInstanceOf(AuthenticatorGetAssertionResponse::class.java)
        Assertions.assertThat(response.statusCode).isEqualTo(StatusCode.CTAP1_ERR_OTHER)
    }

    @Test
    fun getAssertion_test() = runBlockingTest {
        val ctapAuthenticator = CtapAuthenticator()
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
        val response: AuthenticatorGetAssertionResponse = ctapAuthenticator.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(StatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
    }

    @Test
    fun userConsent_false_test() = runBlockingTest {
        val ctapAuthenticator = CtapAuthenticator()
        ctapAuthenticator.userConsentHandler = object : UserConsentHandler {
            override suspend fun consentMakeCredential(options: MakeCredentialConsentOptions): Boolean =
                true

            override suspend fun consentGetAssertion(options: GetAssertionConsentOptions): Boolean =
                false
        }
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
        val response: AuthenticatorGetAssertionResponse = ctapAuthenticator.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(StatusCode.CTAP2_ERR_OPERATION_DENIED)
    }

    @Test
    fun no_credentials_test() = runBlockingTest {
        val ctapAuthenticator = CtapAuthenticator()

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
        val response: AuthenticatorGetAssertionResponse = ctapAuthenticator.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(StatusCode.CTAP2_ERR_NO_CREDENTIALS)
    }

    @Test
    fun options_null_test() = runBlockingTest {
        val ctapAuthenticator = CtapAuthenticator()
        makeCredential(ctapAuthenticator)

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val pinAuth: ByteArray? = null
        val pinProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            null,
            pinAuth,
            pinProtocol
        )
        val response: AuthenticatorGetAssertionResponse = ctapAuthenticator.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(StatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
    }

    @Test
    fun store_full_test() = runBlockingTest {
        var isFull = false
        val authenticatorPropertyStoreSpy =
            object : InMemoryAuthenticatorPropertyStore<Serializable?>() {
                override fun saveUserCredential(userCredential: ResidentUserCredential<Serializable?>) {
                    if (isFull) {
                        throw StoreFullException("AuthenticatorPropertyStore is full")
                    } else {
                        super.saveUserCredential(userCredential)
                    }
                }
            }
        val ctapAuthenticator =
            CtapAuthenticator(authenticatorPropertyStore = authenticatorPropertyStoreSpy)
        makeCredential(ctapAuthenticator)
        isFull = true

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
        val response: AuthenticatorGetAssertionResponse = ctapAuthenticator.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(StatusCode.CTAP2_ERR_KEY_STORE_FULL)
    }

    @ParameterizedTest
    @CsvSource(
        value = [
            "true, SUPPORTED, CTAP2_OK",
            "true, NOT_SUPPORTED, CTAP2_ERR_UNSUPPORTED_OPTION",
            "false, SUPPORTED, CTAP2_OK",
            "false, NOT_SUPPORTED, CTAP2_OK",
        ]
    )
    fun up_userVerification_matrix_test(
        up: Boolean,
        userPresenceSetting: UserPresenceSetting,
        statusCode: StatusCode
    ) = runBlockingTest {
        var ctapAuthenticator = CtapAuthenticator()
        makeCredential(ctapAuthenticator)
        ctapAuthenticator = CtapAuthenticator(
            ctapAuthenticator.attestationStatementGenerator,
            ctapAuthenticator.authenticatorPropertyStore,
            ctapAuthenticator.objectConverter,
            CtapAuthenticatorSettings(userPresence = userPresenceSetting)
        )

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = up, uv = true)
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
        val response: AuthenticatorGetAssertionResponse = ctapAuthenticator.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(statusCode)
    }


    @ParameterizedTest
    @CsvSource(
        value = [
            "true, READY, CTAP2_OK",
            "true, NOT_READY, CTAP2_ERR_UNSUPPORTED_OPTION",
            "true, NOT_SUPPORTED, CTAP2_ERR_UNSUPPORTED_OPTION",
            "false, READY, CTAP2_OK",
            "false, NOT_READY, CTAP2_OK",
            "false, NOT_SUPPORTED, CTAP2_OK",
        ]
    )
    fun uv_userVerification_matrix_test(
        uv: Boolean,
        userVerificationSetting: UserVerificationSetting,
        statusCode: StatusCode
    ) = runBlockingTest {
        val ctapAuthenticator =
            CtapAuthenticator(settings = CtapAuthenticatorSettings(userVerification = userVerificationSetting))
        makeCredential(ctapAuthenticator, uv = false)

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = uv)
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
        val response: AuthenticatorGetAssertionResponse = ctapAuthenticator.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(statusCode)
    }


    @Test
    suspend fun makeCredential(
        ctapAuthenticator: CtapAuthenticator,
        rk: Boolean = true,
        uv: Boolean = true
    ) {
        val clientDataHash = ByteArray(0)
        val rp = PublicKeyCredentialRpEntity("example.com", "example")
        val user = PublicKeyCredentialUserEntity(byteArrayOf(0x01, 0x23), "John.doe", "John Doe")
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
        Assertions.assertThat(response.statusCode).isEqualTo(StatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
        Assertions.assertThat(response.responseData!!.attestationStatement).isNotNull
        Assertions.assertThat(response.responseData!!.authenticatorData).isNotNull
    }
}