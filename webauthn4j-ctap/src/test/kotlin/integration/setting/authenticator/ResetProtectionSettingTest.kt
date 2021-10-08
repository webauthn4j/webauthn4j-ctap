package integration.setting.authenticator

import com.webauthn4j.ctap.authenticator.data.settings.ResetProtectionSetting
import com.webauthn4j.ctap.client.exception.CtapErrorException
import integration.usecase.testcase.ResetTestCase
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE")
@Nested
internal class ResetProtectionSettingTest {
    private val resetTestCase = ResetTestCase()

    @Test
    fun resetProtection_enabled_test() = runBlockingTest {
        resetTestCase.authenticator.resetProtectionSetting = ResetProtectionSetting.ENABLED
        Assertions.assertThatThrownBy {
            runBlockingTest {
                resetTestCase.run()
            }
        }.isInstanceOf(CtapErrorException::class.java)
            .hasMessageContaining("CTAP2_ERR_OPERATION_DENIED")
    }

    @Test
    fun resetProtection_disabled_test() = runBlockingTest {
        resetTestCase.authenticator.resetProtectionSetting = ResetProtectionSetting.DISABLED
        resetTestCase.run()
    }
}