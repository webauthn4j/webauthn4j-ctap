package integration.setting.relyingparty

import com.webauthn4j.data.AuthenticatorAttestationResponse
import com.webauthn4j.data.PublicKeyCredential
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput
import com.webauthn4j.validator.exception.BadOriginException
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock

@Suppress("EXPERIMENTAL_API_USAGE")
internal class OriginTest {
    private val passwordlessTestCase = PasswordlessTestCase()

    @Test
    fun origin_mismatch_test() {
        passwordlessTestCase.relyingParty.registration.frontend.origin =
            Origin("https://example.com")
        passwordlessTestCase.relyingParty.registration.backend.origin =
            Origin("https://mismatch.example.com")
        Assertions.assertThatThrownBy {
            runBlockingTest {
                passwordlessTestCase.run()
            }
        }.isInstanceOf(BadOriginException::class.java)
    }

    @Test
    fun test() {
        val credentialId = ByteArray(0)
        val authenticatorAttestationResponse = mock(AuthenticatorAttestationResponse::class.java)

        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>(
            credentialId,
            authenticatorAttestationResponse,
            null
        )
    }
}