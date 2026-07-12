package com.webauthn4j.ctap.authenticator

import java.time.Duration
import java.time.Instant

class CachingGetAssertionConsentHandler(
    private val delegate: GetAssertionConsentHandler
) : GetAssertionConsentHandler {

    private var cachedRequest: GetAssertionConsentRequest? = null
    private var cachedResult: Boolean? = null
    private var cachedAt: Instant? = null

    override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
        return if (getAssertionConsentRequest == cachedRequest && cachedAt!!.isAfter(Instant.now().minus(TTL))) {
            cachedResult!!
        } else {
            val result = delegate.onGetAssertionConsentRequested(getAssertionConsentRequest)
            cachedRequest = getAssertionConsentRequest
            cachedResult = result
            cachedAt = Instant.now()
            result
        }
    }

    companion object {
        private val TTL = Duration.ofMinutes(1)
    }
}
