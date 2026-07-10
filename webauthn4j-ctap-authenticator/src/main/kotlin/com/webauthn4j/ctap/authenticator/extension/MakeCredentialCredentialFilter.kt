package com.webauthn4j.ctap.authenticator.extension

// Filters the credential list during authenticatorMakeCredential processing like excludeList matching (§6.1.2 Step 12).
// Returns true if the credential should remain visible; false to hide it from excludeList matching.
interface MakeCredentialCredentialFilter : ExtensionProcessor {
    fun test(context: MakeCredentialCredentialFilterContext): Boolean
}
