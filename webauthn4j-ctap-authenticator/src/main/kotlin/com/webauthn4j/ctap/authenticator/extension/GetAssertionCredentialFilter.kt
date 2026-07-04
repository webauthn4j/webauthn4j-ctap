package com.webauthn4j.ctap.authenticator.extension

// Filters the applicable credentials list during authenticatorGetAssertion (§6.2.2 Steps 7.4–7.5).
// Returns true if the credential should remain in the list; false to exclude it.
interface GetAssertionCredentialFilter : ExtensionProcessor {
    fun test(context: GetAssertionCredentialFilterContext): Boolean
}
