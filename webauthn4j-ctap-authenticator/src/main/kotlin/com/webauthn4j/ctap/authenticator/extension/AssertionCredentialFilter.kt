package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.data.PublicKeyCredentialDescriptor

interface AssertionCredentialFilter : ExtensionProcessor {
    fun isAssertionCandidate(
        credential: Credential,
        userVerificationResult: Boolean,
        allowList: List<PublicKeyCredentialDescriptor>?
    ): Boolean
}
