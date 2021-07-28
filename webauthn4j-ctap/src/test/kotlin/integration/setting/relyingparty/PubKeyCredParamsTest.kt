package integration.setting.relyingparty

import com.webauthn4j.ctap.client.exception.CtapErrorException
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import integration.usecase.testcase.PasswordlessTestCase
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE")
class PubKeyCredParamsTest {

    private val passwordlessTestCase = PasswordlessTestCase()

    @Test
    fun pubKeyCredParams_test() {
        passwordlessTestCase.relyingParty.registration.frontend.pubKeyCredParams = listOf(
            PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.RS512
            )
        )
        Assertions.assertThatThrownBy {
            runBlockingTest {
                passwordlessTestCase.run()
            }
        }.isInstanceOf(CtapErrorException::class.java)
            .hasMessageContaining("CTAP2_ERR_UNSUPPORTED_ALGORITHM")
    }
}