package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.execution.GetAssertionExecution
import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.StoreFullException
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionResponse
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.mockito.Mockito.mock

internal class GetAssertionExecutionTest {

    @Disabled
    @Test
    fun createErrorResponse_test() {
        val connection = CtapAuthenticator().createSession()
        val response = GetAssertionExecution(
            connection,
            mock(AuthenticatorGetAssertionRequest::class.java),
        ).createErrorResponse(CtapStatusCode.CTAP1_ERR_OTHER)
        Assertions.assertThat(response).isInstanceOf(AuthenticatorGetAssertionResponse::class.java)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP1_ERR_OTHER)
    }

    @Test
    suspend fun getAssertion_test() {
        val connection = CtapAuthenticator().createSession()
        makeCredential(connection)

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = true)
        val pinUvAuthParam: ByteArray? = null
        val pinUvAuthProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            options,
            pinUvAuthParam,
            pinUvAuthProtocol
        )
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
    }

    @Test
    suspend fun userConsent_false_test() {
        val ctapAuthenticator = CtapAuthenticator()
        val connection = ctapAuthenticator.createSession(
            getAssertionConsentHandler = object : GetAssertionConsentHandler {
                override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean = false
            }
        )
        makeCredential(connection)

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = true)
        val pinUvAuthParam: ByteArray? = null
        val pinUvAuthProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            options,
            pinUvAuthParam,
            pinUvAuthProtocol
        )
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
    }

    @Test
    suspend fun no_credentials_test() {
        val ctapAuthenticator = CtapAuthenticator()
        val connection = ctapAuthenticator.createSession()

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = true)
        val pinUvAuthParam: ByteArray? = null
        val pinUvAuthProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            options,
            pinUvAuthParam,
            pinUvAuthProtocol
        )
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)
    }

    @Test
    suspend fun options_null_test() {
        val ctapAuthenticator = CtapAuthenticator()
        val connection = ctapAuthenticator.createSession()
        makeCredential(connection)

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val pinUvAuthParam: ByteArray? = null
        val pinUvAuthProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            null,
            pinUvAuthParam,
            pinUvAuthProtocol
        )
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
    }

    @Test
    suspend fun store_full_test() {
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
        val connection = ctapAuthenticator.createSession()
        makeCredential(connection)
        isFull = true

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = true)
        val pinUvAuthParam: ByteArray? = null
        val pinUvAuthProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            options,
            pinUvAuthParam,
            pinUvAuthProtocol
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
    suspend fun up_userVerification_matrix_test(
        up: Boolean,
        userPresenceSetting: UserPresenceSetting,
        statusCode: CtapStatusCode
    ) {
        // Create a credential with default settings first,
        // then switch to the target userPresence setting for the GetAssertion test.
        val ctapAuthenticator = CtapAuthenticator()
        val setupConnection = ctapAuthenticator.createSession()
        makeCredential(setupConnection)

        val connection = ctapAuthenticator.copy(userPresence = userPresenceSetting).createSession()

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = up, uv = true)
        val pinUvAuthParam: ByteArray? = null
        val pinUvAuthProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            options,
            pinUvAuthParam,
            pinUvAuthProtocol
        )
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(statusCode)
    }


    @ParameterizedTest
    @CsvSource(
        value = [
            "true, READY, CTAP2_OK",
            "true, NOT_READY, CTAP2_ERR_INVALID_OPTION",
            "true, NOT_SUPPORTED, CTAP2_ERR_INVALID_OPTION",
            "false, READY, CTAP2_OK",
            "false, NOT_READY, CTAP2_OK",
            "false, NOT_SUPPORTED, CTAP2_OK",
        ]
    )
    suspend fun uv_userVerification_matrix_test(
        uv: Boolean,
        userVerificationSetting: UserVerificationSetting,
        statusCode: CtapStatusCode
    ) {
        // Create a credential with default settings (userVerification=READY) first,
        // then switch to the target userVerification setting for the GetAssertion test.
        // This is needed because MakeCredential requires UV on a UV-protected authenticator (Step 8).
        val ctapAuthenticator = CtapAuthenticator()
        val setupConnection = ctapAuthenticator.createSession()
        makeCredential(setupConnection)

        val connection = ctapAuthenticator.copy(userVerification = userVerificationSetting).createSession()

        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = uv)
        val pinUvAuthParam: ByteArray? = null
        val pinUvAuthProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            "example.com",
            clientDataHash,
            allowList,
            extensions,
            options,
            pinUvAuthParam,
            pinUvAuthProtocol
        )
        val response: AuthenticatorGetAssertionResponse = connection.getAssertion(command)
        Assertions.assertThat(response.statusCode).isEqualTo(statusCode)
    }


    private suspend fun makeCredential(
        ctapAuthenticatorSession: CtapAuthenticatorSession,
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
        val pinUvAuthParam: ByteArray? = null
        val pinUvAuthProtocol: PinProtocolVersion? = null
        val command = AuthenticatorMakeCredentialRequest(
            clientDataHash,
            rp,
            user,
            pubKeyCredParams,
            excludeList,
            extensions,
            options,
            pinUvAuthParam,
            pinUvAuthProtocol
        )
        val response = ctapAuthenticatorSession.makeCredential(command)
        Assertions.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        Assertions.assertThat(response.responseData).isNotNull
        Assertions.assertThat(response.responseData!!.attestationStatement).isNotNull
        Assertions.assertThat(response.responseData!!.authenticatorData).isNotNull
    }
}