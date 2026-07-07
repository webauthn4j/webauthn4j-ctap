package integration.usecase

import integration.usecase.testcase.ResetTestCase
import org.junit.jupiter.api.Test

class AuthenticatorResetUseCaseTest {

    @Test
    suspend fun reset_test() {
        val resetTestCase = ResetTestCase()
        resetTestCase.run()
    }
}