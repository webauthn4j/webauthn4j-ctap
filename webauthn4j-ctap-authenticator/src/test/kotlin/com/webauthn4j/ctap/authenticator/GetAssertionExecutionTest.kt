package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.exception.StoreFullException
import com.webauthn4j.ctap.authenticator.execution.GetAssertionExecution
import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionResponse
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.PinProtocolVersion
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.mockito.Mockito.mock

@ExperimentalCoroutinesApi
internal class GetAssertionExecutionTest {

    @Disabled
    @Test
    fun createErrorResponse_test() {
        val connection = CtapAuthenticator().connect()
        val response = GetAssertionExecution(
            connection,
            mock(AuthenticatorGetAssertionRequest::class.java),
        ).createErrorResponse(CtapStatusCode.CTAP1_ERR_OTHER)
        Assertions.assertThat(response).isInstanceOf(AuthenticatorGetAssertionResponse::class.java)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP1_ERR_OTHER)
    }

    @Test
    fun getAssertion_test() = runTest {
        val connection = CtapAuthenticator().connect()
        makeCredential(connection)

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
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
    }

    @Test
    fun userConsent_false_test() = runTest {
        val ctapAuthenticator = CtapAuthenticator()
        ctapAuthenticator.userConsentHandler = object : UserConsentHandler {
            override suspend fun consentMakeCredential(options: MakeCredentialConsentOptions): Boolean =
                true

            override suspend fun consentGetAssertion(options: GetAssertionConsentOptions): Boolean =
                false
        }
        val connection = ctapAuthenticator.connect()
        makeCredential(connection)

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
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
    }

    @Test
    fun no_credentials_test() = runTest {
        val ctapAuthenticator = CtapAuthenticator()
        val connection = ctapAuthenticator.connect()

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
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)
    }

    @Test
    fun options_null_test() = runTest {
        val ctapAuthenticator = CtapAuthenticator()
        val connection = ctapAuthenticator.connect()
        makeCredential(connection)

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
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
    }

    @Test
    fun store_full_test() = runTest {
        var isFull = false
        val authenticatorPropertyStoreSpy =
            object : InMemoryAuthenticatorPropertyStore() {
                override fun saveUserCredential(userCredential: ResidentUserCredential) {
                    if (isFull) {
                        throw StoreFullException("AuthenticatorPropertyStore is full")
                    } else {
                        super.saveUserCredential(userCredential)
                    }
                }
            }
        val ctapAuthenticator = CtapAuthenticator(authenticatorPropertyStore = authenticatorPropertyStoreSpy)
        val connection = ctapAuthenticator.connect()
        makeCredential(connection)
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
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL)
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
        statusCode: CtapStatusCode
    ) = runTest {
        val ctapAuthenticator = CtapAuthenticator()
        val connection = ctapAuthenticator.connect()
        makeCredential(connection)


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

        ctapAuthenticator.userPresence = userPresenceSetting
        val connectionWithUpdatedSetting = ctapAuthenticator.connect()
        val response: AuthenticatorGetAssertionResponse = connectionWithUpdatedSetting.getAssertion(command)
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
        statusCode: CtapStatusCode
    ) = runTest {
        val ctapAuthenticator = CtapAuthenticator()
        ctapAuthenticator.userVerification = userVerificationSetting
        val connection = ctapAuthenticator.connect()
        makeCredential(connection, uv = false)

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
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(statusCode)
    }


    @Test
    suspend fun makeCredential(
        connection: Connection,
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
        val response = connection.makeCredential(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
        Assertions.assertThat(response.responseData!!.attestationStatement).isNotNull
        Assertions.assertThat(response.responseData!!.authenticatorData).isNotNull
    }
}