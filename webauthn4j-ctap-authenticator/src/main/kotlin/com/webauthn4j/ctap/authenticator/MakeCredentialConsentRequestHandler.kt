package com.webauthn4j.ctap.authenticator

fun interface MakeCredentialConsentRequestHandler {

    /**
     * Process makeCredential consent request
     */
    suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean

}