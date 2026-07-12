package com.webauthn4j.ctap.authenticator

import java.time.Duration
import java.time.Instant

class CachingMakeCredentialConsentHandler(
    private val delegate: MakeCredentialConsentHandler
) : MakeCredentialConsentHandler {

    private var cachedRequest: MakeCredentialConsentRequest? = null
    private var cachedResult: Boolean? = null
    private var cachedAt: Instant? = null

    override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
        return if (makeCredentialConsentRequest == cachedRequest && cachedAt!!.isAfter(Instant.now().minus(TTL))) {
            cachedResult!!
        } else {
            val result = delegate.onMakeCredentialConsentRequested(makeCredentialConsentRequest)
            cachedRequest = makeCredentialConsentRequest
            cachedResult = result
            cachedAt = Instant.now()
            result
        }
    }

    companion object {
        private val TTL = Duration.ofMinutes(1)
    }
}
