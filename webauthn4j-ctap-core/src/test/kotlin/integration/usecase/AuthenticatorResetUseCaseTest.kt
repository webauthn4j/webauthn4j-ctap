package integration.usecase

import integration.usecase.testcase.ResetTestCase
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Test

@ExperimentalCoroutinesApi
class AuthenticatorResetUseCaseTest {

    @Test
    fun reset_test() = runBlockingTest {
        val resetTestCase = ResetTestCase()
        resetTestCase.run()
    }
}