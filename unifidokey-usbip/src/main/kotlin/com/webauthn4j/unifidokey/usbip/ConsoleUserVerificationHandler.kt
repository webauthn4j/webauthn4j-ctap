package com.webauthn4j.unifidokey.usbip

import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.UserVerificationHandler
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import kotlinx.coroutines.delay

/**
 * A UserVerificationHandler that auto-approves after a delay.
 * The delay ensures CTAPHID_KEEPALIVE messages are sent by the HID transport layer.
 */
class ConsoleUserVerificationHandler : UserVerificationHandler {

    companion object {
        private const val APPROVAL_DELAY_MS = 1000L
    }

    override fun getUserVerificationOption(rpId: String?): UserVerificationOption =
        UserVerificationOption.READY

    override suspend fun onMakeCredentialConsentRequested(
        makeCredentialConsentRequest: MakeCredentialConsentRequest
    ): Boolean {
        val rpId = makeCredentialConsentRequest.rp?.id ?: "unknown"
        println("MakeCredential consent requested for RP: $rpId (auto-approving in ${APPROVAL_DELAY_MS}ms)")
        delay(APPROVAL_DELAY_MS)
        return true
    }

    override suspend fun onGetAssertionConsentRequested(
        getAssertionConsentRequest: GetAssertionConsentRequest
    ): Boolean {
        val rpId = getAssertionConsentRequest.rpId ?: "unknown"
        println("GetAssertion consent requested for RP: $rpId (auto-approving in ${APPROVAL_DELAY_MS}ms)")
        delay(APPROVAL_DELAY_MS)
        return true
    }
}
