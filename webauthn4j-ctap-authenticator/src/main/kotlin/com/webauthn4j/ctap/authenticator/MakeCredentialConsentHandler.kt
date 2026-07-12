package com.webauthn4j.ctap.authenticator

interface MakeCredentialConsentHandler {
    suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean
}
