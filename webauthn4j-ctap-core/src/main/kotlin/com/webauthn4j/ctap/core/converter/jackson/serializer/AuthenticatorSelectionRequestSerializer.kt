package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorSelectionRequest

class AuthenticatorSelectionRequestSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorSelectionRequest>(
        AuthenticatorSelectionRequest::class.java,
        emptyList()
    )
