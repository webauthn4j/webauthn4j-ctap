package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.StoreFullException
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialResponse
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.CtapStatusCode.Companion.CTAP2_ERR_OPERATION_DENIED
import com.webauthn4j.ctap.core.data.CtapStatusCode.Companion.CTAP2_ERR_UNSUPPORTED_ALGORITHM
import com.webauthn4j.ctap.core.data.PinProtocolVersion
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.mockito.kotlin.any
import org.mockito.kotlin.doThrow
import org.mockito.kotlin.spy

@ExperimentalCoroutinesApi
internal class MakeCredentialExecutionTest {

    @Test
    fun test() = runTest {
        val ctapAuthenticator = CtapAuthenticator()
        val connection = ctapAuthenticator.createSession()

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
        val options = AuthenticatorMakeCredentialRequest.Options(rk = true, uv = true)
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
        assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        assertThat(response.responseData).isNotNull
        assertThat(response.responseData!!.attestationStatement).isNotNull
        assertThat(response.responseData!!.authenticatorData).isNotNull
    }

    @Test
    fun store_full_test() = runTest {
        val ctapAuthenticator = CtapAuthenticator()
        ctapAuthenticator.authenticatorPropertyStore = spy<InMemoryAuthenticatorPropertyStore> {
            onGeneric {
                createUserCredentialKey(
                    any(),
                    any()
                )
            } doThrow StoreFullException("AuthenticatorPropertyStore is full")
        }
        val connection = ctapAuthenticator.createSession()

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
        val options = AuthenticatorMakeCredentialRequest.Options(rk = true, uv = true)
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
        assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_KEY_STORE_FULL)
    }

    @ParameterizedTest
    @CsvSource(
        value = [
            "ALWAYS, CTAP2_OK, 1",
            "IF_REQUIRED, CTAP2_OK, 0",
            "NEVER, CTAP2_OK, 0",
        ]
    )
    fun options_null_residentKey_variation_test(
        residentKeySetting: ResidentKeySetting,
        statusCode: CtapStatusCode,
        createdResidentKeyCount: Int
    ) = runTest {
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
        val pinAuth: ByteArray? = null
        val pinProtocol: PinProtocolVersion? = null
        val command = AuthenticatorMakeCredentialRequest(
            clientDataHash,
            rp,
            user,
            pubKeyCredParams,
            excludeList,
            extensions,
            null,
            pinAuth,
            pinProtocol
        )

        val ctapAuthenticator = CtapAuthenticator()
        ctapAuthenticator.residentKey = residentKeySetting
        val connection = ctapAuthenticator.createSession()

        val response = connection.makeCredential(command)
        assertThat(response).isInstanceOf(AuthenticatorMakeCredentialResponse::class.java)
        assertThat(response.statusCode).isEqualTo(statusCode)
        assertThat(connection.authenticatorPropertyStore.loadUserCredentials("example.com")).hasSize(
            createdResidentKeyCount
        )
    }

    @ParameterizedTest
    @CsvSource(
        value = [
            "true, ALWAYS, CTAP2_OK, 1",
            "true, IF_REQUIRED, CTAP2_OK, 1",
            "true, NEVER, CTAP2_ERR_UNSUPPORTED_OPTION, 0",
            "false, ALWAYS, CTAP2_OK, 1",
            "false, IF_REQUIRED, CTAP2_OK, 0",
            "false, NEVER, CTAP2_OK, 0",
        ]
    )
    fun rk_and_residentKey_matrix_test(
        rk: Boolean,
        residentKeySetting: ResidentKeySetting,
        statusCode: CtapStatusCode,
        createdResidentKeyCount: Int
    ) = runTest {
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
        val options = AuthenticatorMakeCredentialRequest.Options(rk = rk, uv = true)
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

        val ctapAuthenticator = CtapAuthenticator()
        ctapAuthenticator.residentKey = residentKeySetting
        val connection = ctapAuthenticator.createSession()

        val response = connection.makeCredential(command)
        assertThat(response).isInstanceOf(AuthenticatorMakeCredentialResponse::class.java)
        assertThat(response.statusCode).isEqualTo(statusCode)
        assertThat(connection.authenticatorPropertyStore.loadUserCredentials("example.com")).hasSize(
            createdResidentKeyCount
        )
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
    fun uv_and_userVerification_test(
        uv: Boolean,
        userVerificationSetting: UserVerificationSetting,
        statusCode: CtapStatusCode
    ) = runTest {
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
        val options = AuthenticatorMakeCredentialRequest.Options(rk = true, uv = uv)
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

        val ctapAuthenticator = CtapAuthenticator()
        ctapAuthenticator.userVerification = userVerificationSetting
        val connection = ctapAuthenticator.createSession()


        val response = connection.makeCredential(command)
        assertThat(response).isInstanceOf(AuthenticatorMakeCredentialResponse::class.java)
        assertThat(response.statusCode).isEqualTo(statusCode)
    }

    @ParameterizedTest
    @CsvSource(
        value = [
            "SUPPORTED, CTAP2_OK",
            "NOT_SUPPORTED, CTAP2_ERR_UNSUPPORTED_OPTION",
        ]
    )
    fun userPresence_test(userPresenceSetting: UserPresenceSetting, statusCode: CtapStatusCode) =
        runTest {
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
            val options = AuthenticatorMakeCredentialRequest.Options(rk = true, uv = false)
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

            val ctapAuthenticator = CtapAuthenticator()
            ctapAuthenticator.userPresence = userPresenceSetting
            val connection = ctapAuthenticator.createSession()

            val response = connection.makeCredential(command)
            assertThat(response).isInstanceOf(AuthenticatorMakeCredentialResponse::class.java)
            assertThat(response.statusCode).isEqualTo(statusCode)
        }

    @Test
    fun userConsent_false_test() = runTest {
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
        val options = AuthenticatorMakeCredentialRequest.Options(rk = true, uv = true)
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

        val ctapAuthenticator = CtapAuthenticator()
        ctapAuthenticator.userVerificationHandler = object : UserVerificationHandler {
            override fun getUserVerificationOption(rpId: String?): UserVerificationOption = UserVerificationOption.READY
            override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean = false
            override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean = false
        }
        val connection = ctapAuthenticator.createSession()

        val response = connection.makeCredential(command)
        assertThat(response).isInstanceOf(AuthenticatorMakeCredentialResponse::class.java)
        assertThat(response.statusCode).isEqualTo(CTAP2_ERR_OPERATION_DENIED)
    }

    @Test
    fun unsupported_alg_test() = runTest {
        val clientDataHash = ByteArray(0)
        val rp = CtapPublicKeyCredentialRpEntity("example.com", "example", "rpIcon")
        val user = CtapPublicKeyCredentialUserEntity(byteArrayOf(0x01, 0x23), "John.doe", "John Doe", "icon")
        val pubKeyCredParams = listOf(
            PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.RS1
            )
        )
        val excludeList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>()
        val options = AuthenticatorMakeCredentialRequest.Options(rk = true, uv = true)
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

        val ctapAuthenticator = CtapAuthenticator()
        val connection = ctapAuthenticator.createSession()

        val response = connection.makeCredential(command)
        assertThat(response).isInstanceOf(AuthenticatorMakeCredentialResponse::class.java)
        assertThat(response.statusCode).isEqualTo(CTAP2_ERR_UNSUPPORTED_ALGORITHM)
    }

}