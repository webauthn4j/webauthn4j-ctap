package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.authenticator.ClientPINService
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.client.transport.InProcessTransportAdaptor
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runBlockingTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutionException

internal class CtapClientTest {
    private val ctapAuthenticator = CtapAuthenticator()
    private val ctapClient = CtapAuthenticatorHandle(InProcessTransportAdaptor(ctapAuthenticator))
    private val target = CtapClient(ctapClient)

    @ExperimentalCoroutinesApi
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun setPIN_test() = runBlockingTest {
        target.reset()
        target.setPIN("newPIN")
        assertThat(ctapAuthenticator.authenticatorPropertyStore.loadClientPIN()).isEqualTo(
            "newPIN".toByteArray(
                StandardCharsets.UTF_8
            )
        )
    }

    @ExperimentalCoroutinesApi
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun changePIN_test() = runBlockingTest {
        target.reset()
        target.setPIN("currentPIN")
        assertThat(ctapAuthenticator.authenticatorPropertyStore.loadClientPIN()).isEqualTo(
            "currentPIN".toByteArray(
                StandardCharsets.UTF_8
            )
        )
        target.changePIN("currentPIN", "newPIN")
        assertThat(ctapAuthenticator.authenticatorPropertyStore.loadClientPIN()).isEqualTo(
            "newPIN".toByteArray(
                StandardCharsets.UTF_8
            )
        )
    }

    /*ignore exception*/
    @ExperimentalCoroutinesApi
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun getRetries_test() = runBlockingTest {
        assertThat(target.getRetries()).isEqualTo(ClientPINService.MAX_PIN_RETRIES.toLong())
        try {
            target.changePIN("wrongPIN", "newPIN")
        } catch (e: RuntimeException) {
        }
        assertThat(target.getRetries()).isEqualTo((ClientPINService.MAX_PIN_RETRIES - 1).toLong())
        target.reset()
        assertThat(target.getRetries()).isEqualTo(ClientPINService.MAX_PIN_RETRIES.toLong())
    }

    @ExperimentalCoroutinesApi
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun reset_test() = runBlockingTest {
        target.reset()
    }
}