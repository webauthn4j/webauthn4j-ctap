package integration.usecase

import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.client.exception.UPNotSupportedException
import integration.usecase.testcase.SecondFactorTestCase
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE", "ClassName")
internal class AuthenticatorSecondFactorUseCaseTest {
    private val secondFactorTestCase = SecondFactorTestCase()

    @Nested
    internal inner class residentKey_setting_test {

        @Test
        suspend fun residentKey_always_test() {
            secondFactorTestCase.authenticator.residentKeySetting = ResidentKeySetting.ALWAYS
            secondFactorTestCase.run()
        }

        @Test
        suspend fun residentKey_if_required_test() {
            secondFactorTestCase.authenticator.residentKeySetting = ResidentKeySetting.IF_REQUIRED
            secondFactorTestCase.run()
        }

        // TODO: This test fails because the client sends rk=false even when GetInfo does not
        //  report rk support. The authenticator correctly rejects this per Step 5.4.1.
        //  Once CtapService is fixed to send rk=null (absent) when GetInfo lacks rk,
        //  this test should pass without throwing and the @Disabled can be removed.
        @Disabled
        @Test
        suspend fun residentKey_never_test() {
            secondFactorTestCase.authenticator.residentKeySetting = ResidentKeySetting.NEVER
            secondFactorTestCase.run()
        }
    }

    @Nested
    internal inner class clientPIN_userVerification_setting_correlation_test {
        @Test
        suspend fun clientPIN_enabled_userVerification_ready_test() {
            secondFactorTestCase.authenticator.clientPINSetting = ClientPINSetting.ENABLED
            secondFactorTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.READY
            secondFactorTestCase.run()
        }

        @Test
        suspend fun clientPIN_enabled_userVerification_not_ready_test() {
            secondFactorTestCase.authenticator.clientPINSetting = ClientPINSetting.ENABLED
            secondFactorTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.NOT_READY
            secondFactorTestCase.run()
        }

        @Test
        suspend fun clientPIN_disabled_userVerification_ready_test() {
            secondFactorTestCase.authenticator.clientPINSetting = ClientPINSetting.DISABLED
            secondFactorTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.READY
            secondFactorTestCase.run()
        }

        @Test
        suspend fun clientPIN_disabled_userVerification_not_ready_test() {
            secondFactorTestCase.authenticator.clientPINSetting = ClientPINSetting.DISABLED
            secondFactorTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.NOT_READY
            secondFactorTestCase.run()
        }

        @Test
        suspend fun clientPIN_disabled_userVerification_not_supported_test() {
            secondFactorTestCase.authenticator.clientPINSetting = ClientPINSetting.DISABLED
            secondFactorTestCase.authenticator.userVerificationSetting =
                UserVerificationSetting.NOT_SUPPORTED
            secondFactorTestCase.run()
        }
    }

    @Nested
    internal inner class userPresence_setting_test {
        @Test
        suspend fun userPresence_supported_test() {
            secondFactorTestCase.authenticator.userPresenceSetting = UserPresenceSetting.SUPPORTED
            secondFactorTestCase.run()
        }

        @Test
        fun userPresence_not_supported_test() {
            Assertions.assertThatThrownBy {
                runTest {
                    secondFactorTestCase.authenticator.userPresenceSetting =
                        UserPresenceSetting.NOT_SUPPORTED
                    secondFactorTestCase.run()
                }
            }.isInstanceOf(UPNotSupportedException::class.java)
        }
    }
}