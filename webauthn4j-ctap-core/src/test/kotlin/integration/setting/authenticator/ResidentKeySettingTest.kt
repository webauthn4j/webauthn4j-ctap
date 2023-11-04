package integration.setting.authenticator

import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE")
class ResidentKeySettingTest {

    private val passwordlessTestCase = PasswordlessTestCase()

    @Test
    fun residentKey_always_test() = runTest {
        passwordlessTestCase.authenticator.residentKeySetting = ResidentKeySetting.ALWAYS
        passwordlessTestCase.run()
    }

    @Test
    fun residentKey_if_required_test() = runTest {
        passwordlessTestCase.authenticator.residentKeySetting = ResidentKeySetting.IF_REQUIRED
        passwordlessTestCase.run()
    }

    @Test
    fun residentKey_never_test() {
        passwordlessTestCase.authenticator.residentKeySetting = ResidentKeySetting.NEVER
        assertThatThrownBy {
            runTest {
                passwordlessTestCase.run()
            }
        }.isInstanceOf(WebAuthnClientException::class.java)
            .hasMessageContaining("Matching authenticator doesn't exist.")
    }
}