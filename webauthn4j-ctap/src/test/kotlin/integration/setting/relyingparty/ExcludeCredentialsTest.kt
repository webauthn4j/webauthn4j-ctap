package integration.setting.relyingparty

import com.webauthn4j.ctap.authenticator.CredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.store.Credential
import com.webauthn4j.ctap.client.exception.CtapErrorException
import com.webauthn4j.data.*
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE")
class ExcludeCredentialsTest {
    private val passwordlessTestCase = PasswordlessTestCase()

    @Test
    fun excludeCredentials_test() {
        assertThatThrownBy {
            runBlockingTest {
                var result: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>? =
                    null
                passwordlessTestCase.authenticator.credentialSelectorSetting =
                    CredentialSelectorSetting.AUTHENTICATOR
                passwordlessTestCase.authenticator.credentialSelectionHandler =
                    object : CredentialSelectionHandler {
                        override suspend fun select(list: List<Credential>): Credential {
                            return list.first { item -> item.credentialId.contentEquals(result?.rawId) }
                        }
                    }
                result = passwordlessTestCase.step1_createCredential() //create a credential
                passwordlessTestCase.relyingParty.registration.frontend.excludeCredentials = listOf(
                    PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        result.rawId,
                        setOf(AuthenticatorTransport.USB)
                    )
                ) // exclude the created credential
                passwordlessTestCase.step1_createCredential() // create a credential with exclude option
            }
        }.isInstanceOf(CtapErrorException::class.java)
            .hasMessageContaining("CTAP2_ERR_CREDENTIAL_EXCLUDED")
    }

    @Test
    fun excludeCredentials_other_authenticator_test() = runBlockingTest {
        var result: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>? =
            null
        passwordlessTestCase.authenticator.credentialSelectorSetting =
            CredentialSelectorSetting.AUTHENTICATOR
        passwordlessTestCase.authenticator.credentialSelectionHandler =
            object : CredentialSelectionHandler {
                override suspend fun select(list: List<Credential>): Credential {
                    return list.first { item -> item.credentialId.contentEquals(result?.rawId) }
                }
            }
        result = passwordlessTestCase.step1_createCredential() //create a credential
        val otherAuthenticatorCredentialId = ByteArray(32)
        passwordlessTestCase.relyingParty.registration.frontend.excludeCredentials = listOf(
            PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                otherAuthenticatorCredentialId,
                setOf(AuthenticatorTransport.USB)
            )
        ) // exclude an other authenticator credential
        passwordlessTestCase.step1_createCredential() // create a credential with exclude option
    }
}