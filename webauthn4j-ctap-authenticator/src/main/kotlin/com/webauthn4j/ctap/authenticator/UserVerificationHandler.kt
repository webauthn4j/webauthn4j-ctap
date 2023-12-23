package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.options.UserVerificationOption

interface UserVerificationHandler {

    fun getUserVerificationOption(rpId: String?): UserVerificationOption?

    /**
     * Process makeCredential consent request
     */
    suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean

    /**
     * Process getAssertion consent request
     */
    suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean

}