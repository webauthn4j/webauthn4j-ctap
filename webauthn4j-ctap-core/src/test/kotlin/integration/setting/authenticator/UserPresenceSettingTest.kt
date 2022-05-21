package integration.setting.authenticator

import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.client.exception.UPNotSupportedException
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE")
class UserPresenceSettingTest {
    private val passwordlessTestCase = PasswordlessTestCase()

    @Test
    fun userPresence_supported_test() = runBlockingTest {
        passwordlessTestCase.authenticator.userPresenceSetting = UserPresenceSetting.SUPPORTED
        passwordlessTestCase.run()
    }

    @Test
    fun userPresence_not_supported_test() {
        passwordlessTestCase.authenticator.userPresenceSetting = UserPresenceSetting.NOT_SUPPORTED
        assertThatThrownBy {
            runBlockingTest {
                passwordlessTestCase.run()
            }
        }.isInstanceOf(UPNotSupportedException::class.java)
            .hasMessageContaining("Authenticator doesn't support test of user presence.")
    }
}