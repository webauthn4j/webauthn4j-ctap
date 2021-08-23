package integration.setting.authenticator

import com.webauthn4j.ctap.authenticator.CredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.store.Credential
import com.webauthn4j.ctap.client.PublicKeyCredentialSelectionHandler
import com.webauthn4j.data.AuthenticatorAssertionResponse
import com.webauthn4j.data.AuthenticatorAttestationResponse
import com.webauthn4j.data.PublicKeyCredential
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput
import com.webauthn4j.validator.exception.BadSignatureException
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE", "ClassName")
class CredentialSelectorSettingTest {
    private val passwordlessTestCase = PasswordlessTestCase()

    @Nested
    inner class credentialSelector_authenticator {
        @Test
        fun correct_selection_test() = runBlockingTest {
            var publicKeyCredential: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>? =
                null

            passwordlessTestCase.authenticator.credentialSelectorSetting =
                CredentialSelectorSetting.AUTHENTICATOR
            passwordlessTestCase.authenticator.credentialSelectionHandler = object : CredentialSelectionHandler { // This credentialSelectionHandler selects 2nd (correct) credential
                override suspend fun select(list: List<Credential>): Credential {
                    return list.first { it.credentialId.contentEquals(publicKeyCredential!!.rawId) }
                }
            }
            passwordlessTestCase.step1_createCredential() // create a credential (1st)
            publicKeyCredential =
                passwordlessTestCase.step1_createCredential() // create a credential (2nd)
            passwordlessTestCase.step2_validateCredentialForRegistration()
            passwordlessTestCase.step3_getCredential()
            passwordlessTestCase.step4_validateCredentialForAuthentication()
        }

        @Test
        fun incorrect_selection_test() = runBlockingTest {
            var publicKeyCredential: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>? =
                null

            passwordlessTestCase.authenticator.credentialSelectorSetting =
                CredentialSelectorSetting.AUTHENTICATOR
            passwordlessTestCase.authenticator.credentialSelectionHandler = object :
                CredentialSelectionHandler { // This credentialSelectionHandler selects 1st (incorrect) credential
                override suspend fun select(list: List<Credential>): Credential {
                    return list.first { it.credentialId.contentEquals(publicKeyCredential!!.rawId) }
                }
            }
            publicKeyCredential =
                passwordlessTestCase.step1_createCredential() // create a credential (1st)
            passwordlessTestCase.step1_createCredential() // create a credential (2nd)
            passwordlessTestCase.step2_validateCredentialForRegistration()
            passwordlessTestCase.step3_getCredential()
            Assertions.assertThatThrownBy {
                runBlockingTest {
                    passwordlessTestCase.step4_validateCredentialForAuthentication()
                }
            }.isInstanceOf(BadSignatureException::class.java)
                .hasMessageContaining("Assertion signature is not valid.")
        }
    }


    @Nested
    inner class credentialSelector_client_platform {

        @Test
        fun correct_selection_test() = runBlockingTest {

            var publicKeyCredential: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>? =
                null

            passwordlessTestCase.authenticator.credentialSelectorSetting =
                CredentialSelectorSetting.CLIENT_PLATFORM
            passwordlessTestCase.clientPlatform.webAuthnAPIClient.publicKeyCredentialSelectionHandler =
                object : PublicKeyCredentialSelectionHandler {
                    override fun select(list: List<PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>>): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
                        return list.first { it.rawId.contentEquals(publicKeyCredential!!.rawId) }
                    }
                }

            passwordlessTestCase.step1_createCredential() // create a credential (1st)
            publicKeyCredential =
                passwordlessTestCase.step1_createCredential() // create a credential (2nd)
            passwordlessTestCase.step2_validateCredentialForRegistration()
            passwordlessTestCase.step3_getCredential()
            passwordlessTestCase.step4_validateCredentialForAuthentication()
        }

        @Test
        fun incorrect_selection_test() = runBlockingTest {
            var publicKeyCredential: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>? =
                null

            passwordlessTestCase.authenticator.credentialSelectorSetting =
                CredentialSelectorSetting.CLIENT_PLATFORM
            passwordlessTestCase.clientPlatform.webAuthnAPIClient.publicKeyCredentialSelectionHandler =
                object : PublicKeyCredentialSelectionHandler {
                    override fun select(list: List<PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>>): PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> {
                        return list.first { it.rawId.contentEquals(publicKeyCredential!!.rawId) }
                    }
                }

            publicKeyCredential =
                passwordlessTestCase.step1_createCredential() // create a credential (1st)
            passwordlessTestCase.step1_createCredential() // create a credential (2nd)
            passwordlessTestCase.step2_validateCredentialForRegistration()
            passwordlessTestCase.step3_getCredential()
            Assertions.assertThatThrownBy {
                runBlockingTest {
                    passwordlessTestCase.step4_validateCredentialForAuthentication()
                }
            }.isInstanceOf(BadSignatureException::class.java)
                .hasMessageContaining("Assertion signature is not valid.")
        }

    }


}