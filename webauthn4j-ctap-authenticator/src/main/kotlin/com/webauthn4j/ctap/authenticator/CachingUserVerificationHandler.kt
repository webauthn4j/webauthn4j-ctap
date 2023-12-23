package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import java.time.Duration
import java.time.Instant

/**
 * [GetAssertionConsentRequestHandler] implementation which caches consent result
 */
class CachingUserVerificationHandler(
    private val userVerificationHandler: UserVerificationHandler
) :
    UserVerificationHandler {
    private var cachedMakeCredentialConsentRequest: MakeCredentialConsentRequest? = null
    private var cachedMakeCredentialConsentResult: Boolean? = null
    private var makeCredentialConsentCachedAt: Instant? = null

    private var cachedGetAssertionConsentRequest: GetAssertionConsentRequest? = null
    private var cachedGetAssertionConsentResult: Boolean? = null
    private var getAssertionConsentCachedAt: Instant? = null
    override fun getUserVerificationOption(rpId: String?): UserVerificationOption? =
        userVerificationHandler.getUserVerificationOption(rpId)

    override suspend fun onMakeCredentialConsentRequested(makeCredentialConsentRequest: MakeCredentialConsentRequest): Boolean {
        return if (makeCredentialConsentRequest == cachedMakeCredentialConsentRequest && makeCredentialConsentCachedAt!!.isAfter(
                Instant.now().minus(TTL)
            )
        ) {
            cachedMakeCredentialConsentResult!!
        } else {
            val result = userVerificationHandler.onMakeCredentialConsentRequested(makeCredentialConsentRequest)
            cachedMakeCredentialConsentRequest = makeCredentialConsentRequest
            cachedMakeCredentialConsentResult = result
            makeCredentialConsentCachedAt = Instant.now()
            result
        }
    }

    override suspend fun onGetAssertionConsentRequested(getAssertionConsentRequest: GetAssertionConsentRequest): Boolean {
        return if (getAssertionConsentRequest == cachedGetAssertionConsentRequest && getAssertionConsentCachedAt!!.isAfter(
                Instant.now().minus(TTL)
            )
        ) {
            cachedGetAssertionConsentResult!!
        } else {
            val result = userVerificationHandler.onGetAssertionConsentRequested(getAssertionConsentRequest)
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
