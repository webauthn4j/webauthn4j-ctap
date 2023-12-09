package com.webauthn4j.ctap.authenticator

import java.time.Duration
import java.time.Instant

/**
 * [GetAssertionConsentRequestHandler] implementation which caches consent result
 */
class CachingMakeCredentialConsentRequestHandler(
    private val makeCredentialConsentRequestHandler: MakeCredentialConsentRequestHandler
) :
    MakeCredentialConsentRequestHandler {
    private var cachedMakeCredentialConsentRequest: MakeCredentialConsentRequest? = null
    private var cachedMakeCredentialConsentResult: Boolean? = null
    private var makeCredentialConsentCachedAt: Instant? = null

    override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
        return if (makeCredentialConsentRequest == cachedMakeCredentialConsentRequest && makeCredentialConsentCachedAt!!.isAfter(
                Instant.now().minus(TTL)
            )
        ) {
            cachedMakeCredentialConsentResult!!
        } else {
            val result = makeCredentialConsentRequestHandler.onMakeCredentialConsentRequested(makeCredentialConsentRequest)
            cachedMakeCredentialConsentRequest = makeCredentialConsentRequest
            cachedMakeCredentialConsentResult = result
            makeCredentialConsentCachedAt = Instant.now()
            result
        }
    }

    companion object {
        private val TTL = Duration.ofMinutes(1)
    }
}
