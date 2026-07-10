package com.webauthn4j.unifidokey.usbip

import com.webauthn4j.ctap.authenticator.GetAssertionConsentHandler
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentHandler
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.SelectionHandler
import com.webauthn4j.ctap.authenticator.UserVerificationCapabilityProvider
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import kotlinx.coroutines.delay
import org.slf4j.LoggerFactory

class ConsoleUserConsentHandler :
    UserVerificationCapabilityProvider,
    MakeCredentialConsentHandler,
    GetAssertionConsentHandler,
    SelectionHandler {

    private val logger = LoggerFactory.getLogger(ConsoleUserConsentHandler::class.java)

    companion object {
        private const val APPROVAL_DELAY_MS = 1000L
    }

    override fun getUserVerificationOption(rpId: String?): UserVerificationOption =
        UserVerificationOption.READY

    override suspend fun onMakeCredentialConsentRequested(
        makeCredentialConsentRequest: MakeCredentialConsentRequest
    ): Boolean {
        val rpId = makeCredentialConsentRequest.rp?.id ?: "unknown"
        logger.info("MakeCredential consent requested for RP: {} (auto-approving in {}ms)", rpId, APPROVAL_DELAY_MS)
        delay(APPROVAL_DELAY_MS)
        return true
    }

    override suspend fun onGetAssertionConsentRequested(
        getAssertionConsentRequest: GetAssertionConsentRequest
    ): Boolean {
        val rpId = getAssertionConsentRequest.rpId ?: "unknown"
        logger.info("GetAssertion consent requested for RP: {} (auto-approving in {}ms)", rpId, APPROVAL_DELAY_MS)
        delay(APPROVAL_DELAY_MS)
        return true
    }

    override suspend fun onSelectionRequested(): Boolean {
        logger.info("Selection consent requested (auto-approving in {}ms)", APPROVAL_DELAY_MS)
        delay(APPROVAL_DELAY_MS)
        return true
    }
}
