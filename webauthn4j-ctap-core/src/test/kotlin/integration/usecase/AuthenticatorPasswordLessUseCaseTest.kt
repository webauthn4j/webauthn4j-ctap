package integration.usecase

import integration.usecase.testcase.PasswordlessTestCase
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE")
internal class AuthenticatorPasswordLessUseCaseTest {

    @Test
    suspend fun passwordless_test() {
        val passwordlessTestCase = PasswordlessTestCase()
        passwordlessTestCase.run()
    }
}