package com.webauthn4j.ctap.authenticator

import androidx.test.core.app.ApplicationProvider
import com.google.common.truth.Truth
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.driver.persistence.UnifidoKeyAuthenticatorPropertyStoreImpl
import com.unifidokey.driver.persistence.dao.AndroidKeyStoreDao
import com.unifidokey.driver.persistence.dao.KeyStoreDao
import com.unifidokey.driver.persistence.dao.PreferenceDao
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.NoneAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import com.webauthn4j.util.exception.UnexpectedCheckedException
import kotlinx.coroutines.test.runBlockingTest
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.io.Serializable
import java.util.concurrent.ExecutionException

@Suppress("EXPERIMENTAL_API_USAGE")
class CtapAuthenticatorTest {
    private lateinit var ctapAuthenticator: CtapAuthenticator
    private lateinit var authenticatorPropertyStore: AuthenticatorPropertyStore<Serializable?>

    @Before
    fun setup() {
        val application = ApplicationProvider.getApplicationContext<UnifidoKeyHandHeldApplication>()
        val unifidoKeyHandHeldComponent = application.unifidoKeyComponent
        val objectConverter = ObjectConverter()
        val attestationStatementProvider: AttestationStatementProvider =
            NoneAttestationStatementProvider()
        val relyingPartyDao = application.unifidoKeyComponent.relyingPartyDao
        val userCredentialDao = unifidoKeyHandHeldComponent.userCredentialDao
        val preferenceDao = PreferenceDao(application)
        val configManager = ConfigManager(preferenceDao)
        val keyStoreDao: KeyStoreDao = AndroidKeyStoreDao()
        authenticatorPropertyStore = UnifidoKeyAuthenticatorPropertyStoreImpl(
            relyingPartyDao,
            userCredentialDao,
            configManager,
            keyStoreDao
        )
        ctapAuthenticator = CtapAuthenticator(
            attestationStatementProvider,
            authenticatorPropertyStore,
            objectConverter,
            CtapAuthenticatorSettings()
        )
    }

    @After
    fun teardown() {
        authenticatorPropertyStore.clear()
    }

    @Test
    fun makeCredential_test() = runBlockingTest {
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
        val options = AuthenticatorMakeCredentialRequest.Options(rk = true, uv = true)
        val pinAuth: ByteArray? = null
        val pinProtocol: PinProtocolVersion? = null
        val makeCredentialCommand = AuthenticatorMakeCredentialRequest(
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
        val response: AuthenticatorMakeCredentialResponse =
            ctapAuthenticator.makeCredential(makeCredentialCommand)
        Truth.assertThat(response).isNotNull()
        Truth.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
    }

    @Test
    fun getAssertion_test() = runBlockingTest {
        makeCredential()
        val rpId = "example.com"
        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = true)
        val pinAuth: ByteArray? = null
        val pinProtocol: PinProtocolVersion? = null
        val getAssertionCommand = AuthenticatorGetAssertionRequest(
            rpId,
            clientDataHash,
            allowList,
            extensions,
            options,
            pinAuth,
            pinProtocol
        )
        val response: AuthenticatorGetAssertionResponse =
            ctapAuthenticator.getAssertion(getAssertionCommand)
        Truth.assertThat(response).isNotNull()
        Truth.assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
    }

    private suspend fun makeCredential(): AuthenticatorMakeCredentialResponse {
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
        return try {
            ctapAuthenticator.makeCredential(command)
        } catch (e: InterruptedException) {
            throw UnexpectedCheckedException(e)
        } catch (e: ExecutionException) {
            throw UnexpectedCheckedException(e)
        }
    }
}