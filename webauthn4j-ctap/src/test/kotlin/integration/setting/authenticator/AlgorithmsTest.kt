package integration.setting.authenticator

import com.webauthn4j.ctap.client.exception.CtapErrorException
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.authenticator.RSACOSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.util.concurrent.ExecutionException

@Suppress("EXPERIMENTAL_API_USAGE", "ClassName")
class AlgorithmsTest {
    private val passwordlessTestCase = PasswordlessTestCase()

    @Nested
    internal inner class rp_requests_ES256 {
        @BeforeEach
        fun setup() {
            passwordlessTestCase.relyingParty.registration.frontend.pubKeyCredParams =
                listOf(
                    PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.ES256
                    )
                )
        }

        @Test
        @Throws(ExecutionException::class, InterruptedException::class)
        fun authenticator_supports_ES256_test() = runBlockingTest {
            passwordlessTestCase.authenticator.algorithms = setOf(COSEAlgorithmIdentifier.ES256)
            passwordlessTestCase.step1_createCredential()
            val registrationData = passwordlessTestCase.step2_validateCredentialForRegistration()
            Assertions.assertThat(registrationData.attestationObject!!.authenticatorData.attestedCredentialData!!.coseKey)
                .isInstanceOf(EC2COSEKey::class.java)
            passwordlessTestCase.step3_getCredential()
            passwordlessTestCase.step4_validateCredentialForAuthentication()
        }

        @Test
        fun authenticator_supports_RS256_test() {
            passwordlessTestCase.authenticator.algorithms = setOf(COSEAlgorithmIdentifier.RS256)
            Assertions.assertThatThrownBy {
                runBlockingTest {
                    passwordlessTestCase.run()
                }
            }.isInstanceOf(CtapErrorException::class.java)
                .hasMessageContaining("CTAP2_ERR_UNSUPPORTED_ALGORITHM")
        }
    }

    @Nested
    internal inner class rp_requests_RS256 {
        @BeforeEach
        fun setup() {
            passwordlessTestCase.relyingParty.registration.frontend.pubKeyCredParams =
                listOf(
                    PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.RS256
                    )
                )
        }

        @Test
        fun authenticator_supports_ES256_test() {
            passwordlessTestCase.authenticator.algorithms = setOf(COSEAlgorithmIdentifier.ES256)
            Assertions.assertThatThrownBy {
                runBlockingTest {
                    passwordlessTestCase.run()
                }
            }.isInstanceOf(CtapErrorException::class.java)
                .hasMessageContaining("CTAP2_ERR_UNSUPPORTED_ALGORITHM")
        }

        @Test
        @Throws(ExecutionException::class, InterruptedException::class)
        fun authenticator_supports_RS256_test() = runBlockingTest {
            passwordlessTestCase.authenticator.algorithms = setOf(COSEAlgorithmIdentifier.RS256)
            passwordlessTestCase.step1_createCredential()
            val registrationData = passwordlessTestCase.step2_validateCredentialForRegistration()
            Assertions.assertThat(registrationData.attestationObject!!.authenticatorData.attestedCredentialData!!.coseKey)
                .isInstanceOf(RSACOSEKey::class.java)
            passwordlessTestCase.step3_getCredential()
            passwordlessTestCase.step4_validateCredentialForAuthentication()
        }
    }

    @Nested
    internal inner class rp_requests_RS1 {
        @BeforeEach
        fun setup() {
            passwordlessTestCase.relyingParty.registration.frontend.pubKeyCredParams =
                listOf(
                    PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.RS1
                    )
                )
        }

        @Test
        @Throws(ExecutionException::class, InterruptedException::class)
        fun authenticator_supports_RS1_test() = runBlockingTest {
            passwordlessTestCase.authenticator.algorithms = setOf(COSEAlgorithmIdentifier.RS1)
            passwordlessTestCase.step1_createCredential()
            val registrationData = passwordlessTestCase.step2_validateCredentialForRegistration()
            Assertions.assertThat(registrationData.attestationObject!!.authenticatorData.attestedCredentialData!!.coseKey)
                .isInstanceOf(RSACOSEKey::class.java)
            passwordlessTestCase.step3_getCredential()
            passwordlessTestCase.step4_validateCredentialForAuthentication()
        }
    }
}