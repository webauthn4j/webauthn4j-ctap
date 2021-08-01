package com.unifidokey.app.handheld.presentation

import com.webauthn4j.ctap.authenticator.GetAssertionConsentOptions
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentOptions
import com.webauthn4j.ctap.authenticator.UserConsentHandler
import java.time.Duration
import java.time.Instant

class CachingUserConsentHandler(private val userConsentHandler: UserConsentHandler) :
    UserConsentHandler {
    private var cachedMakeCredentialConsentOptions: MakeCredentialConsentOptions? = null
    private var cachedMakeCredentialConsentResult: Boolean? = null
    private var makeCredentialConsentCachedAt: Instant? = null
    private var cachedGetAssertionConsentOptions: GetAssertionConsentOptions? = null
    private var cachedGetAssertionConsentResult: Boolean? = null
    private var getAssertionConsentCachedAt: Instant? = null

    override suspend fun consentMakeCredential(options: MakeCredentialConsentOptions): Boolean {
        return if (options == cachedMakeCredentialConsentOptions && makeCredentialConsentCachedAt!!.isAfter(
                Instant.now().minus(TTL)
            )
        ) {
            cachedMakeCredentialConsentResult!!
        } else {
            val result = userConsentHandler.consentMakeCredential(options)
            cachedMakeCredentialConsentOptions = options
            cachedMakeCredentialConsentResult = result
            makeCredentialConsentCachedAt = Instant.now()
            result
        }
    }

    override suspend fun consentGetAssertion(options: GetAssertionConsentOptions): Boolean {
        return if (options == cachedGetAssertionConsentOptions && getAssertionConsentCachedAt!!.isAfter(
                Instant.now().minus(TTL)
            )
        ) {
            cachedGetAssertionConsentResult!!
        } else {
            val result = userConsentHandler.consentGetAssertion(options)
            cachedGetAssertionConsentOptions = options
            cachedGetAssertionConsentResult = result
            getAssertionConsentCachedAt = Instant.now()
            result
        }
    }

    companion object {
        private val TTL = Duration.ofMinutes(1)
    }
}