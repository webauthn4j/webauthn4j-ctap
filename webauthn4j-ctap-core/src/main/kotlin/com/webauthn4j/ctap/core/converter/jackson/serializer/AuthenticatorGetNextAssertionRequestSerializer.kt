package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionRequest

class AuthenticatorGetNextAssertionRequestSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetNextAssertionRequest>(
        AuthenticatorGetNextAssertionRequest::class.java,
        emptyList()
    )
