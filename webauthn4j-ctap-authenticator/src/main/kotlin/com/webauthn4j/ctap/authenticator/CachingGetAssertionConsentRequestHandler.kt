package com.webauthn4j.ctap.authenticator

import java.time.Duration
import java.time.Instant

/**
 * [GetAssertionConsentRequestHandler] implementation which caches consent result
 */
class CachingGetAssertionConsentRequestHandler(private val getAssertionConsentRequestHandler: GetAssertionConsentRequestHandler) :
    GetAssertionConsentRequestHandler {

    private var cachedGetAssertionConsentRequest: GetAssertionConsentRequest? = null
    private var cachedGetAssertionConsentResult: Boolean? = null
    private var getAssertionConsentCachedAt: Instant? = null


    override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
        return if (getAssertionConsentRequest == cachedGetAssertionConsentRequest && getAssertionConsentCachedAt!!.isAfter(
                Instant.now().minus(TTL)
            )
        ) {
            cachedGetAssertionConsentResult!!
        } else {
            val result = getAssertionConsentRequestHandler.onGetAssertionConsentRequested(getAssertionConsentRequest)
            cachedGetAssertionConsentRequest = getAssertionConsentRequest
            cachedGetAssertionConsentResult = result
            getAssertionConsentCachedAt = Instant.now()
            result
        }
    }

    companion object {
        private val TTL = Duration.ofMinutes(1)
    }
}
