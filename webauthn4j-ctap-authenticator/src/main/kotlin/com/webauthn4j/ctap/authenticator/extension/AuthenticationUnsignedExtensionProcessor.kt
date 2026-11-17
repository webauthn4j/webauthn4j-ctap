package com.webauthn4j.ctap.authenticator.extension

/** Invoked for the selected assertion only, after successful user authorization. */
interface AuthenticationUnsignedExtensionProcessor : ExtensionProcessor {
    fun processAuthentication(context: AuthenticationExtensionContext): Any?
}
