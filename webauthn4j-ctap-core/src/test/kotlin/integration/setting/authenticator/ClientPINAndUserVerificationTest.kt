package integration.setting.authenticator

import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE", "ClassName")
class ClientPINAndUserVerificationTest {
    private val passwordlessTestCase = PasswordlessTestCase()

    @Nested
    internal inner class clientPIN_enabled {

        @BeforeEach
        fun setup() {
            passwordlessTestCase.authenticator.clientPINSetting = ClientPINSetting.ENABLED
        }

        @Test
        fun userVerification_ready_test() = runTest {
            passwordlessTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.READY
            passwordlessTestCase.run()
        }

        @Test
        fun userVerification_not_ready_test() = runTest {
            passwordlessTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.NOT_READY
            passwordlessTestCase.run()
        }
    }

    @Nested
    internal inner class clientPIN_disabled {

        @BeforeEach
        fun setup() {
            passwordlessTestCase.authenticator.clientPINSetting = ClientPINSetting.DISABLED
        }

        @Test
        fun userVerification_ready_test() = runTest {
            passwordlessTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.READY
            passwordlessTestCase.run()
        }

        @Test
        fun userVerification_not_ready_test() {
            passwordlessTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.NOT_READY
            assertThatThrownBy {
                runTest {
                    passwordlessTestCase.run()
                }
            }.isInstanceOf(WebAuthnClientException::class.java)
                .hasMessageContaining("Matching authenticator doesn't exist.")
        }

        @Test
        fun userVerification_not_supported_test() {
            passwordlessTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.NOT_SUPPORTED
            assertThatThrownBy {
                runTest {
                    passwordlessTestCase.run()
                }
            }.isInstanceOf(WebAuthnClientException::class.java)
                .hasMessageContaining("Matching authenticator doesn't exist.")
        }
    }
}