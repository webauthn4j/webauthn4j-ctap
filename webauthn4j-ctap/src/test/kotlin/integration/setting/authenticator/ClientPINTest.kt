package integration.setting.authenticator

import com.webauthn4j.ctap.authenticator.ClientPINService
import com.webauthn4j.ctap.authenticator.settings.ClientPINSetting
import com.webauthn4j.ctap.client.exception.CtapErrorException
import integration.usecase.testcase.ClientPINTestCase
import kotlinx.coroutines.test.runBlockingTest
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
                runBlockingTest {
                    clientPINTestCase.clientPlatform.ctapService.setPIN("new-PIN")
                }
            }.isInstanceOf(CtapErrorException::class.java)
                .hasMessageContaining("CTAP2_ERR_PIN_AUTH_INVALID")
        }

        @Test
        fun pin_not_already_set_test() = runBlockingTest {
            clientPINTestCase.clientPlatform.ctapService.reset()
            clientPINTestCase.clientPlatform.ctapService.setPIN("new-PIN")
        }
    }

    @Test
    fun changePIN_test() = runBlockingTest {
        clientPINTestCase.clientPlatform.ctapService.changePIN("clientPIN", "new-PIN")
    }

    @Test
    fun changePIN_with_invalid_PIN_and_reach_MAX_VOLATILE_PIN_RETRIES_test() = runBlockingTest {
        repeat(3) {
            assertThatThrownBy {
                runBlockingTest {
                    clientPINTestCase.clientPlatform.ctapService.changePIN(
                        "invalid-PIN",
                        "invalid-PIN"
                    )
                }
            }.isInstanceOf(CtapErrorException::class.java)
                .hasMessageContaining("CTAP2_ERR_PIN_INVALID")
        }
        assertThatThrownBy {
            runBlockingTest {
                clientPINTestCase.clientPlatform.ctapService.changePIN("invalid-PIN", "invalid-PIN")
            }
        }.isInstanceOf(CtapErrorException::class.java)
            .hasMessageContaining("CTAP2_ERR_PIN_AUTH_BLOCKED")
    }

    @Test
    fun changePIN_with_invalid_PIN_and_reach_MAX_PIN_RETRIES_test() = runBlockingTest {
        repeat(8) {
            assertThatThrownBy {
                runBlockingTest {
                    clientPINTestCase.clientPlatform.ctapService.changePIN(
                        "invalid-PIN",
                        "invalid-PIN"
                    )
                }
            }.isInstanceOf(CtapErrorException::class.java)
                .hasMessageContaining("CTAP2_ERR_PIN_INVALID")

            clientPINTestCase.authenticator.ctapAuthenticator.clientPINService.resetVolatilePinRetryCounter() // reset volatile PIN retries
        }
        assertThatThrownBy {
            runBlockingTest {
                clientPINTestCase.clientPlatform.ctapService.changePIN("invalid-PIN", "invalid-PIN")
            }
        }.isInstanceOf(CtapErrorException::class.java).hasMessageContaining("CTAP2_ERR_PIN_BLOCKED")

    }


    @Test
    fun getRetries_test() = runBlockingTest {
        assertThat(clientPINTestCase.clientPlatform.ctapService.getRetries().toInt()).isEqualTo(
            ClientPINService.MAX_PIN_RETRIES
        )
        try {
            clientPINTestCase.clientPlatform.ctapService.changePIN("invalid-PIN", "invalid-PIN")
        } catch (e: CtapErrorException) { /* nop */
        }
        assertThat(clientPINTestCase.clientPlatform.ctapService.getRetries().toInt()).isEqualTo(
            ClientPINService.MAX_PIN_RETRIES - 1
        )
    }

    @Disabled
    @Test
    fun clientPINSetting_DISABLED_test() = runBlockingTest {
        clientPINTestCase.authenticator.clientPINSetting = ClientPINSetting.ENABLED
        clientPINTestCase.clientPlatform.ctapService.setPIN("dummy")
    }


}