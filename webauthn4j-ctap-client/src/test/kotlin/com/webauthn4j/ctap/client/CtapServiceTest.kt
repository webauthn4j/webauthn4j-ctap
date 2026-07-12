package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.authenticator.PinUvAuthManager
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.GetAssertionConsentHandler
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentHandler
import com.webauthn4j.ctap.authenticator.UserVerificationCapabilityProvider
import com.webauthn4j.ctap.authenticator.transport.internal.InternalTransport
import com.webauthn4j.ctap.client.transport.InProcessAdaptor
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.util.MessageDigestUtil
import com.webauthn4j.data.AuthenticatorAttachment
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutionException

internal class CtapServiceTest {
    private val ctapAuthenticator = CtapAuthenticator()
    private val connection = ctapAuthenticator.createSession()
    private val ctapClient = CtapClient(InProcessAdaptor(InternalTransport(ctapAuthenticator,
        object : UserVerificationCapabilityProvider {
            override fun getUserVerificationOption(rpId: String?): UserVerificationOption? = UserVerificationOption.NOT_SUPPORTED
        },
        object : MakeCredentialConsentHandler {
            override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean = true
        },
        object : GetAssertionConsentHandler {
            override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean = true
        }
    )))
    private val target = CtapService(ctapClient)

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    suspend fun setPIN_test() {
        target.reset()
        target.setPIN("newPIN")
        assertThat(connection.authenticatorPropertyStore.loadClientPIN()).isEqualTo(
            pinHash("newPIN")
        )
    }

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    suspend fun changePIN_test() {
        target.reset()
        target.setPIN("currentPIN")
        assertThat(connection.authenticatorPropertyStore.loadClientPIN()).isEqualTo(
            pinHash("currentPIN")
        )
        target.changePIN("currentPIN", "newPIN")
        assertThat(connection.authenticatorPropertyStore.loadClientPIN()).isEqualTo(
            pinHash("newPIN")
        )
    }

    private fun pinHash(pin: String): ByteArray {
        return java.util.Arrays.copyOf(
            MessageDigestUtil.createSHA256().digest(pin.toByteArray(StandardCharsets.UTF_8)), 16
        )
    }

    /*ignore exception*/
    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    suspend fun getRetries_test() {
        assertThat(target.getRetries()).isEqualTo(PinUvAuthManager.MAX_PIN_RETRIES)
        try {
            target.changePIN("wrongPIN", "newPIN")
        } catch (e: RuntimeException) {
        }
        assertThat(target.getRetries()).isEqualTo(PinUvAuthManager.MAX_PIN_RETRIES - 1u)
        target.reset()
        assertThat(target.getRetries()).isEqualTo(PinUvAuthManager.MAX_PIN_RETRIES)
    }

    @Test
    @Throws(ExecutionException::class, InterruptedException::class)
    suspend fun reset_test() {
        target.reset()
    }
}