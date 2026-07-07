package integration.setting.relyingparty

import com.webauthn4j.converter.AttestationObjectConverter
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement
import integration.usecase.testcase.PasswordlessTestCase
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

class AttestationTest {

    private val passwordlessTestCase = PasswordlessTestCase()


    @Test
    suspend fun attestation_none_test() {
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
    suspend fun attestation_indirect_test() {
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
    suspend fun attestation_direct_test() {
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