package integration.setting.authenticator

import com.webauthn4j.ctap.authenticator.data.settings.PlatformSetting
import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import com.webauthn4j.data.AuthenticatorAttachment
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.util.concurrent.ExecutionException

@Suppress("EXPERIMENTAL_API_USAGE", "ClassName")
class PlatformSettingTest {
    private val passwordlessTestCase = PasswordlessTestCase()

    @Nested
    internal inner class authenticatorAttachment_platform {
        @BeforeEach
        fun setup() {
            passwordlessTestCase.relyingParty.registration.frontend.authenticatorAttachment =
                AuthenticatorAttachment.PLATFORM
        }

        @Test
        @Throws(ExecutionException::class, InterruptedException::class)
        fun platform_platform_test() = runTest {
            passwordlessTestCase.authenticator.platformSetting = PlatformSetting.PLATFORM
            passwordlessTestCase.run()
        }

        @Test
        fun platform_cross_platform_test() {
            passwordlessTestCase.authenticator.platformSetting = PlatformSetting.CROSS_PLATFORM
            assertThatThrownBy {
                runTest {
                    passwordlessTestCase.run()
                }
            }.isInstanceOf(WebAuthnClientException::class.java)
                .hasMessageContaining("Matching authenticator doesn't exist.")
        }
    }

    @Nested
    internal inner class authenticatorAttachment_cross_platform {
        @BeforeEach
        fun setup() {
            passwordlessTestCase.relyingParty.registration.frontend.authenticatorAttachment =
                AuthenticatorAttachment.CROSS_PLATFORM
        }

        @Test
        fun platform_platform_test() {
            passwordlessTestCase.authenticator.platformSetting = PlatformSetting.PLATFORM
            assertThatThrownBy {
                runTest {
                    passwordlessTestCase.run()
                }
            }.isInstanceOf(WebAuthnClientException::class.java)
                .hasMessageContaining("Matching authenticator doesn't exist.")
        }

        @Test
        @Throws(ExecutionException::class, InterruptedException::class)
        fun platform_cross_platform_test() = runTest {
            passwordlessTestCase.authenticator.platformSetting = PlatformSetting.CROSS_PLATFORM
            passwordlessTestCase.run()
        }
    }

    @Nested
    internal inner class authenticatorAttachment_undefined {

        @BeforeEach
        fun setup() {
            passwordlessTestCase.relyingParty.registration.frontend.authenticatorAttachment = null
        }

        @Test
        @Throws(ExecutionException::class, InterruptedException::class)
        fun platform_platform_test() = runTest {
            passwordlessTestCase.authenticator.platformSetting = PlatformSetting.PLATFORM
            passwordlessTestCase.run()
        }

        @Test
        @Throws(ExecutionException::class, InterruptedException::class)
        fun platform_cross_platform_test() = runTest {
            passwordlessTestCase.authenticator.platformSetting = PlatformSetting.CROSS_PLATFORM
            passwordlessTestCase.run()
        }
    }
}