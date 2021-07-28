package integration.setting.authenticator

import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FAttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.attestation.NoneAttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.attestation.PackedAttestationStatementGenerator
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement
import com.webauthn4j.test.TestAttestationUtil
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import java.util.concurrent.ExecutionException

@Suppress("EXPERIMENTAL_API_USAGE")
class AttestationStatementGeneratorTest {

    private val passwordlessTestCase = PasswordlessTestCase()

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun attestationStatementGenerator_packed_test() = runBlockingTest {
        passwordlessTestCase.authenticator.attestationStatementGenerator =
            PackedAttestationStatementGenerator.createWithDemoAttestation()
        passwordlessTestCase.step1_createCredential()
        val registrationData = passwordlessTestCase.step2_validateCredentialForRegistration()
        Assertions.assertThat(registrationData.attestationObject!!.attestationStatement)
            .isInstanceOf(PackedAttestationStatement::class.java)
        passwordlessTestCase.step3_getCredential()
        passwordlessTestCase.step4_validateCredentialForAuthentication()
    }

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun attestationStatementGenerator_fido_u2f_test() = runBlockingTest {
        val privateKey = TestAttestationUtil.load2tierTestAuthenticatorAttestationPrivateKey()
        val attestationCertificate =
            TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate()
        passwordlessTestCase.authenticator.attestationStatementGenerator =
            FIDOU2FAttestationStatementGenerator(privateKey, attestationCertificate)
        passwordlessTestCase.authenticator.aaguid = AAGUID.ZERO
        passwordlessTestCase.step1_createCredential()
        val registrationData = passwordlessTestCase.step2_validateCredentialForRegistration()
        Assertions.assertThat(registrationData.attestationObject!!.attestationStatement)
            .isInstanceOf(FIDOU2FAttestationStatement::class.java)
        passwordlessTestCase.step3_getCredential()
        passwordlessTestCase.step4_validateCredentialForAuthentication()
    }

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun attestationStatementGenerator_none_test() = runBlockingTest {
        passwordlessTestCase.authenticator.attestationStatementGenerator =
            NoneAttestationStatementGenerator()
        passwordlessTestCase.authenticator.aaguid = AAGUID.ZERO
        passwordlessTestCase.step1_createCredential()
        val registrationData = passwordlessTestCase.step2_validateCredentialForRegistration()
        Assertions.assertThat(registrationData.attestationObject!!.attestationStatement)
            .isInstanceOf(NoneAttestationStatement::class.java)
        passwordlessTestCase.step3_getCredential()
        passwordlessTestCase.step4_validateCredentialForAuthentication()
    }
}