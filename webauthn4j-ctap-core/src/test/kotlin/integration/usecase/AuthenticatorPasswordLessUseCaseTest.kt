package integration.usecase

import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runBlockingTest
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE")
internal class AuthenticatorPasswordLessUseCaseTest {

    @Test
    fun passwordless_test() = runBlockingTest {
        val passwordlessTestCase = PasswordlessTestCase()
        passwordlessTestCase.run()
    }
}