package integration.setting.authenticator

import com.webauthn4j.data.attestation.authenticator.AAGUID
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.*
import java.util.concurrent.ExecutionException

@Suppress("EXPERIMENTAL_API_USAGE")
class AAGUIDTest {
    private val passwordlessTestCase = PasswordlessTestCase()

    @ExperimentalCoroutinesApi
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun aaguid_custom_test() = runTest {
        val aaguid = AAGUID(UUID.randomUUID())
        passwordlessTestCase.authenticator.aaguid = aaguid
        passwordlessTestCase.step1_createCredential()
        val registrationData = passwordlessTestCase.step2_validateCredentialForRegistration()
        assertThat(registrationData.attestationObject!!.authenticatorData.attestedCredentialData!!.aaguid).isEqualTo(
            aaguid
        )
        passwordlessTestCase.step3_getCredential()
        passwordlessTestCase.step4_validateCredentialForAuthentication()
    }
}