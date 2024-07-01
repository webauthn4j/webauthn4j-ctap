@file:Suppress("ClassName")

package integration.setting.relyingparty

import com.webauthn4j.verifier.exception.BadRpIdException
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE", "ClassName")
class RpIdTest {

    private val passwordlessTestCase = PasswordlessTestCase()

    @Nested
    internal inner class registration_test {

        @BeforeEach
        fun setup() {
            passwordlessTestCase.relyingParty.registration.frontend.rpId = "example.com"
        }

        @Test
        fun frontend_rpId_null_test() = runTest {
            passwordlessTestCase.relyingParty.registration.frontend.rpId = null
            passwordlessTestCase.run()
        }

        @Test
        fun frontend_backend_rpId_match_test() = runTest {
            passwordlessTestCase.relyingParty.registration.backend.rpId = "example.com"
            passwordlessTestCase.run()
        }

        @Test
        fun frontend_backend_rpId_mismatch_test() {
            passwordlessTestCase.relyingParty.registration.backend.rpId = "bad-rp-id.example.com"
            Assertions.assertThatThrownBy {
                runTest {
                    passwordlessTestCase.run()
                }
            }.isInstanceOf(BadRpIdException::class.java)
                .hasMessageContaining("rpIdHash doesn't match the hash of preconfigured rpId.")
        }
    }

    @Nested
    internal inner class authentication_test {

        @BeforeEach
        fun setup() {
            passwordlessTestCase.relyingParty.authentication.frontend.rpId = "example.com"
        }

        @Test
        fun frontend_rpId_null_test() = runTest {
            passwordlessTestCase.relyingParty.authentication.frontend.rpId = null
            passwordlessTestCase.run()
        }

        @Test
        fun frontend_backend_rpId_match_test() = runTest {
            passwordlessTestCase.relyingParty.authentication.backend.rpId = "example.com"
            passwordlessTestCase.run()
        }

        @Test
        fun frontend_backend_rpId_mismatch_test() {
            passwordlessTestCase.relyingParty.authentication.backend.rpId = "bad-rp-id.example.com"
            Assertions.assertThatThrownBy {
                runTest {
                    passwordlessTestCase.run()
                }
            }.isInstanceOf(BadRpIdException::class.java)
                .hasMessageContaining("rpIdHash doesn't match the hash of preconfigured rpId.")
        }

        @Test
        fun registration_authentication_rpId_mismatch_test() {
            passwordlessTestCase.relyingParty.authentication.backend.rpId =
                "authentication.example.com"
            passwordlessTestCase.relyingParty.authentication.backend.rpId =
                "authentication.example.com"
            Assertions.assertThatThrownBy {
                runTest {
                    passwordlessTestCase.run()
                }
            }.isInstanceOf(BadRpIdException::class.java)
                .hasMessageContaining("rpIdHash doesn't match the hash of preconfigured rpId.")
        }
    }


}