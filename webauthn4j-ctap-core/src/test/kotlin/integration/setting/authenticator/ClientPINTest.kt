package integration.setting.authenticator

import com.webauthn4j.ctap.authenticator.ClientPINService
import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.transport.internal.InternalTransport
import com.webauthn4j.ctap.client.CtapClient
import com.webauthn4j.ctap.client.exception.CtapErrorException
import com.webauthn4j.ctap.client.transport.InProcessAdaptor
import integration.usecase.testcase.ClientPINTestCase
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@Suppress("EXPERIMENTAL_API_USAGE", "ClassName")
class ClientPINTest {

    private val clientPINTestCase = ClientPINTestCase()

    @Nested
    internal inner class setPIN {

        @Test
        fun pin_already_set_test() {
            assertThatThrownBy {
                runTest {
                    clientPINTestCase.clientPlatform.ctapService.setPIN("new-PIN")
                }
            }.isInstanceOf(CtapErrorException::class.java)
                .hasMessageContaining("CTAP2_ERR_PIN_AUTH_INVALID")
        }

        @Test
        fun pin_not_already_set_test() = runTest {
            clientPINTestCase.clientPlatform.ctapService.reset()
            clientPINTestCase.clientPlatform.ctapService.setPIN("new-PIN")
        }
    }

    @Test
    fun changePIN_test() = runTest {
        clientPINTestCase.clientPlatform.ctapService.changePIN("clientPIN", "new-PIN")
    }

    @Test
    fun changePIN_with_invalid_PIN_and_reach_MAX_VOLATILE_PIN_RETRIES_test() {
        repeat(3) {
            assertThatThrownBy {
                runTest {
                    clientPINTestCase.clientPlatform.ctapService.changePIN(
                        "invalid-PIN",
                        "invalid-PIN"
                    )
                }
            }.isInstanceOf(CtapErrorException::class.java)
                .hasMessageContaining("CTAP2_ERR_PIN_INVALID")
        }
        assertThatThrownBy {
            runTest {
                clientPINTestCase.clientPlatform.ctapService.changePIN("invalid-PIN", "invalid-PIN")
            }
        }.isInstanceOf(CtapErrorException::class.java)
            .hasMessageContaining("CTAP2_ERR_PIN_AUTH_BLOCKED")
    }

    @Test
    fun changePIN_with_invalid_PIN_and_reach_MAX_PIN_RETRIES_test() {
        repeat(8) {
            assertThatThrownBy {
                runTest {
                    clientPINTestCase.clientPlatform.ctapService.changePIN(
                        "invalid-PIN",
                        "invalid-PIN"
                    )
                }
            }.isInstanceOf(CtapErrorException::class.java).hasMessageContaining("CTAP2_ERR_PIN_INVALID")

            clientPINTestCase.authenticator.transport = InternalTransport(clientPINTestCase.authenticator.ctapAuthenticator, clientPINTestCase.authenticator.userVerificationHandler) //renew transport to reset session and reset volatile PIN retries
        }
        assertThatThrownBy {
            runTest {
                clientPINTestCase.clientPlatform.ctapService.changePIN("invalid-PIN", "invalid-PIN")
            }
        }.isInstanceOf(CtapErrorException::class.java).hasMessageContaining("CTAP2_ERR_PIN_BLOCKED")

    }


    @Test
    fun getRetries_test() = runTest {
        assertThat(clientPINTestCase.clientPlatform.ctapService.getRetries()).isEqualTo(ClientPINService.MAX_PIN_RETRIES)
        try {
            clientPINTestCase.clientPlatform.ctapService.changePIN("invalid-PIN", "invalid-PIN")
        } catch (e: CtapErrorException) { /* nop */
        }
        assertThat(clientPINTestCase.clientPlatform.ctapService.getRetries()).isEqualTo(ClientPINService.MAX_PIN_RETRIES - 1u)
    }

    @Disabled
    @Test
    fun clientPINSetting_DISABLED_test() = runTest {
        clientPINTestCase.authenticator.clientPINSetting = ClientPINSetting.ENABLED
        clientPINTestCase.clientPlatform.ctapService.setPIN("dummy")
    }


}