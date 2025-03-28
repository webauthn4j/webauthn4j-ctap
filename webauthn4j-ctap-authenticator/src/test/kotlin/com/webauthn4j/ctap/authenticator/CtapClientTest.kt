package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.data.options.*
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import com.webauthn4j.util.exception.UnexpectedCheckedException
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import java.util.concurrent.ExecutionException

@Suppress("EXPERIMENTAL_API_USAGE")
internal class CtapClientTest {
    private val connection = CtapAuthenticator().createSession()

    @Test
    fun getInfo_test() = runTest {
        val response = connection.getInfo()
        Assertions.assertThat(response.responseData).isNotNull
        Assertions.assertThat(response.responseData!!.aaguid).isEqualTo(CtapAuthenticator.AAGUID)
        Assertions.assertThat(response.responseData!!.versions)
            .isEqualTo(CtapAuthenticator.VERSIONS)
        Assertions.assertThat(response.responseData!!.pinProtocols)
            .isEqualTo(CtapAuthenticator.PIN_PROTOCOLS)
        Assertions.assertThat(response.responseData!!.options).isNotNull
        Assertions.assertThat(response.responseData!!.options!!.plat)
            .isEqualTo(PlatformOption.CROSS_PLATFORM)
        Assertions.assertThat(response.responseData!!.options!!.rk)
            .isEqualTo(ResidentKeyOption.SUPPORTED)
        Assertions.assertThat(response.responseData!!.options!!.clientPin)
            .isEqualTo(ClientPINOption.NOT_SET)
        Assertions.assertThat(response.responseData!!.options!!.up)
            .isEqualTo(UserPresenceOption.SUPPORTED)
        Assertions.assertThat(response.responseData!!.options!!.uv)
            .isEqualTo(UserVerificationOption.READY)

    }

    @Test
    fun getAssertion_test() = runTest {
        makeCredential()
        val clientDataHash = ByteArray(0)
        val allowList: List<PublicKeyCredentialDescriptor> = emptyList()
        val extensions =
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>()
        val options = AuthenticatorGetAssertionRequest.Options(up = true, uv = true)
        val pinAuth: ByteArray? = null
        val pinProtocol: PinProtocolVersion? = null
        val command = AuthenticatorGetAssertionRequest(
            RP_ID,
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
    fun reset_test() = runTest {
        makeCredential()
        Assertions.assertThat(connection.authenticatorPropertyStore.loadUserCredentials(RP_ID))
            .hasSize(1)
        connection.reset()
        Assertions.assertThat(connection.authenticatorPropertyStore.loadUserCredentials(RP_ID))
            .isEmpty()
        Assertions.assertThat(connection.authenticatorPropertyStore.loadClientPIN()).isNull()
    }

    private suspend fun makeCredential(): AuthenticatorMakeCredentialResponse {
        val clientDataHash = ByteArray(0)
        val rp = CtapPublicKeyCredentialRpEntity(RP_ID, "example", "rpIcon")
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
        return try {
            connection.makeCredential(command)
        } catch (e: InterruptedException) {
            throw UnexpectedCheckedException(e)
        } catch (e: ExecutionException) {
            throw UnexpectedCheckedException(e)
        }
    }

    companion object {
        private const val RP_ID = "example.com"
    }
}