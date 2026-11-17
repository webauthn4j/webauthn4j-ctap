package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.UserCredentialBuilder

/** Extension results placed in the CTAP response, outside signed authenticator data. */
interface RegistrationUnsignedExtensionProcessor : ExtensionProcessor {
    fun processRegistration(context: RegistrationExtensionContext, builder: UserCredentialBuilder): Any?
}
