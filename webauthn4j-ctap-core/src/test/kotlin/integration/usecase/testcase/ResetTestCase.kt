package integration.usecase.testcase

import com.webauthn4j.ctap.core.data.AuthenticatorResetRequest

open class ResetTestCase : IntegrationTestCaseBase() {

    suspend fun run() {

        val resetCommand = AuthenticatorResetRequest()
        clientPlatform.ctapClient.reset(resetCommand)

    }
}