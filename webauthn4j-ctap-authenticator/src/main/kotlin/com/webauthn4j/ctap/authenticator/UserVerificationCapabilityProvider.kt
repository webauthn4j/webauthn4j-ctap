package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.options.UserVerificationOption

interface UserVerificationCapabilityProvider {
    fun getUserVerificationOption(rpId: String?): UserVerificationOption?
}
