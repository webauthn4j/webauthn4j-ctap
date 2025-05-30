package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.authenticator.ClientPINService
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.UserVerificationHandler
import com.webauthn4j.ctap.authenticator.transport.internal.InternalTransport
import com.webauthn4j.ctap.client.transport.InProcessAdaptor
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.AuthenticatorAttachment
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutionException

internal class CtapServiceTest {
    private val ctapAuthenticator = CtapAuthenticator()
    private val connection = ctapAuthenticator.createSession()
    private val ctapClient = CtapClient(InProcessAdaptor(InternalTransport(ctapAuthenticator,
        object : UserVerificationHandler {
            override fun getUserVerificationOption(rpId: String?): UserVerificationOption? {
                return UserVerificationOption.NOT_SUPPORTED
            }

            override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
                return true
            }

            override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
                return true
            }

        })))
    private val target = CtapService(ctapClient)

    @ExperimentalCoroutinesApi
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun setPIN_test() = runTest {
        target.reset()
        target.setPIN("newPIN")
        assertThat(connection.authenticatorPropertyStore.loadClientPIN()).isEqualTo(
            "newPIN".toByteArray(
                StandardCharsets.UTF_8
            )
        )
    }

    @ExperimentalCoroutinesApi
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun changePIN_test() = runTest {
        target.reset()
        target.setPIN("currentPIN")
        assertThat(connection.authenticatorPropertyStore.loadClientPIN()).isEqualTo(
            "currentPIN".toByteArray(
                StandardCharsets.UTF_8
            )
        )
        target.changePIN("currentPIN", "newPIN")
        assertThat(connection.authenticatorPropertyStore.loadClientPIN()).isEqualTo(
            "newPIN".toByteArray(
                StandardCharsets.UTF_8
            )
        )
    }

    /*ignore exception*/
    @ExperimentalCoroutinesApi
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun getRetries_test() = runTest {
        assertThat(target.getRetries()).isEqualTo(ClientPINService.MAX_PIN_RETRIES)
        try {
            target.changePIN("wrongPIN", "newPIN")
        } catch (e: RuntimeException) {
        }
        assertThat(target.getRetries()).isEqualTo(ClientPINService.MAX_PIN_RETRIES - 1u)
        target.reset()
        assertThat(target.getRetries()).isEqualTo(ClientPINService.MAX_PIN_RETRIES)
    }

    @ExperimentalCoroutinesApi
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    fun reset_test() = runTest {
        target.reset()
    }
}