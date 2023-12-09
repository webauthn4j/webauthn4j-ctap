package integration.setting.relyingparty

import com.webauthn4j.converter.AttestationObjectConverter
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

@ExperimentalCoroutinesApi
class AttestationTest {

    private val passwordlessTestCase = PasswordlessTestCase()


    @Test
    fun attestation_none_test() = runTest {
        passwordlessTestCase.relyingParty.registration.frontend.attestation =
            AttestationConveyancePreference.NONE

        passwordlessTestCase.step1_createCredential()
        val attestationObject =
            AttestationObjectConverter(passwordlessTestCase.objectConverter).convert(
                passwordlessTestCase.step1Result.response?.attestationObject
            )
        assertThat(attestationObject!!.format).isEqualTo(NoneAttestationStatement.FORMAT)
    }

    @Disabled
    @Test
    fun attestation_indirect_test() = runTest {
        passwordlessTestCase.relyingParty.registration.frontend.attestation =
            AttestationConveyancePreference.INDIRECT

        passwordlessTestCase.step1_createCredential()
        val attestationObject =
            AttestationObjectConverter(passwordlessTestCase.objectConverter).convert(
                passwordlessTestCase.step1Result.response?.attestationObject
            )
        assertThat(attestationObject!!.format).isEqualTo(NoneAttestationStatement.FORMAT)
    }

    @Test
    fun attestation_direct_test() = runTest {
        passwordlessTestCase.relyingParty.registration.frontend.attestation =
            AttestationConveyancePreference.DIRECT

        passwordlessTestCase.step1_createCredential()
        val attestationObject =
            AttestationObjectConverter(passwordlessTestCase.objectConverter).convert(
                passwordlessTestCase.step1Result.response?.attestationObject
            )
        assertThat(attestationObject!!.format).isEqualTo(PackedAttestationStatement.FORMAT)
    }

}