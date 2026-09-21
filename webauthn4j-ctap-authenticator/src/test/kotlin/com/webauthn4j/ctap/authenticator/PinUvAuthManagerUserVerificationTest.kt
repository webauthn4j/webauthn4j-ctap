package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermission
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermissions
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.data.attestation.authenticator.COSEKey
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock

internal class PinUvAuthManagerUserVerificationTest {

    @Test
    fun `internal retry stops after verification succeeds`() = runTest {
        val store = InMemoryAuthenticatorPropertyStore()
        val results = ArrayDeque<BuiltInUserVerificationAttemptResult>().apply {
            add(BuiltInUserVerificationAttemptResult.Invalid)
            add(BuiltInUserVerificationAttemptResult.Invalid)
            add(BuiltInUserVerificationAttemptResult.Verified(userPresent = true))
        }
        val manager = manager(
            store = store,
            verificationHandler = BuiltInUserVerificationHandler { results.removeFirst() },
        )

        val result = manager.performBuiltInUserVerification(internalRetry = true)

        assertThat(result).isEqualTo(BuiltInUserVerificationResult.Verified(userPresent = true))
        assertThat(store.loadUVRetries()).isEqualTo(PinUvAuthManager.MAX_UV_RETRIES)
        assertThat(results).isEmpty()
    }

    @Test
    fun `single failed attempt decrements retries`() = runTest {
        val store = InMemoryAuthenticatorPropertyStore()
        val manager = manager(
            store = store,
            verificationHandler = BuiltInUserVerificationHandler {
                BuiltInUserVerificationAttemptResult.Invalid
            },
        )

        val result = manager.performBuiltInUserVerification(internalRetry = false)

        assertThat(result).isEqualTo(BuiltInUserVerificationResult.Invalid)
        assertThat(store.loadUVRetries()).isEqualTo(PinUvAuthManager.MAX_UV_RETRIES - 1u)
    }

    @Test
    fun `timeout does not consume a retry`() = runTest {
        val store = InMemoryAuthenticatorPropertyStore()
        val manager = manager(
            store = store,
            verificationHandler = BuiltInUserVerificationHandler {
                BuiltInUserVerificationAttemptResult.UserActionTimeout
            },
        )

        val result = manager.performBuiltInUserVerification(internalRetry = false)

        assertThat(result).isEqualTo(BuiltInUserVerificationResult.UserActionTimeout)
        assertThat(store.loadUVRetries()).isEqualTo(PinUvAuthManager.MAX_UV_RETRIES)
    }

    @Test
    fun `consent rejection does not issue a token`() = runTest {
        val store = InMemoryAuthenticatorPropertyStore()
        val protocol = FakePinUvAuthProtocol()
        var verificationRequested = false
        val manager = manager(
            store = store,
            protocol = protocol,
            consentHandler = PinUvAuthTokenConsentHandler { false },
            verificationHandler = BuiltInUserVerificationHandler {
                verificationRequested = true
                BuiltInUserVerificationAttemptResult.Verified(userPresent = true)
            },
        )

        val response = manager.getPinUvAuthTokenUsingUvWithPermissions(
            PinProtocolVersion.VERSION_1,
            mock(COSEKey::class.java),
            PinUvAuthTokenPermissions(PinUvAuthTokenPermission.MC),
            "example.com",
        )

        assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_ERR_OPERATION_DENIED)
        assertThat(protocol.resetCount).isZero()
        assertThat(protocol.tokenState.isInUse()).isFalse()
        assertThat(verificationRequested).isFalse()
    }

    @Test
    fun `verified request issues a scoped token`() = runTest {
        val store = InMemoryAuthenticatorPropertyStore()
        val protocol = FakePinUvAuthProtocol()
        val permissions = PinUvAuthTokenPermissions(PinUvAuthTokenPermission.GA)
        val manager = manager(store = store, protocol = protocol)

        val response = manager.getPinUvAuthTokenUsingUvWithPermissions(
            PinProtocolVersion.VERSION_1,
            mock(COSEKey::class.java),
            permissions,
            "example.com",
        )

        assertThat(response.statusCode).isEqualTo(CtapStatusCode.CTAP2_OK)
        assertThat(protocol.resetCount).isEqualTo(1)
        assertThat(protocol.tokenState.getUserVerifiedFlagValue()).isTrue()
        assertThat(protocol.tokenState.getUserPresentFlagValue()).isTrue()
        assertThat(protocol.tokenState.permissions).isEqualTo(permissions)
        assertThat(protocol.tokenState.permissionsRpId).isEqualTo("example.com")
    }

    private fun manager(
        store: InMemoryAuthenticatorPropertyStore,
        protocol: FakePinUvAuthProtocol = FakePinUvAuthProtocol(),
        consentHandler: PinUvAuthTokenConsentHandler = PinUvAuthTokenConsentHandler { true },
        verificationHandler: BuiltInUserVerificationHandler = BuiltInUserVerificationHandler {
            BuiltInUserVerificationAttemptResult.Verified(userPresent = true)
        },
    ) = PinUvAuthManager(
        store,
        listOf(protocol),
        object : UserVerificationCapabilityProvider {
            override fun getUserVerificationOption(rpId: String?): UserVerificationOption =
                UserVerificationOption.READY
        },
        consentHandler,
        verificationHandler,
    )

    private class FakePinUvAuthProtocol : PinUvAuthProtocol {
        override val version = PinProtocolVersion.VERSION_1
        override val pinUvAuthToken = ByteArray(16) { 1 }
        override val tokenState = PinUvAuthTokenState()
        var resetCount = 0

        override fun initialize() = Unit
        override fun regenerate() = Unit
        override fun resetPinUvAuthToken() {
            resetCount++
            tokenState.stopUsingPinUvAuthToken()
        }
        override fun getPublicKey(): COSEKey = mock(COSEKey::class.java)
        override fun decapsulate(peerCoseKey: COSEKey): ByteArray = ByteArray(32) { 2 }
        override fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray = plaintext
        override fun decrypt(key: ByteArray, ciphertext: ByteArray): ByteArray = ciphertext
        override fun authenticate(key: ByteArray, message: ByteArray): ByteArray = message
        override fun verify(key: ByteArray, message: ByteArray, signature: ByteArray): Boolean = true
    }
}
