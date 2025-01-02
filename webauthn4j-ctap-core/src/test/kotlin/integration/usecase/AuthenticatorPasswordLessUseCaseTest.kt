package integration.usecase

import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE")
internal class AuthenticatorPasswordLessUseCaseTest {

    @Test
    fun passwordless_test() = runTest {
        val passwordlessTestCase = PasswordlessTestCase()
        passwordlessTestCase.run()
    }
}