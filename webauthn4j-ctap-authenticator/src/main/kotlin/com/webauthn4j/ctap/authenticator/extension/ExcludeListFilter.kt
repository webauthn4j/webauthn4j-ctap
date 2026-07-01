package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.data.credential.Credential

interface ExcludeListFilter : ExtensionProcessor {
    fun isExcludeListCandidate(
        credential: Credential,
        pinAuthPresent: Boolean
    ): Boolean
}
