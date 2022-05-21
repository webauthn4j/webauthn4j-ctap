package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoRequest

class AuthenticatorGetInfoRequestSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetInfoRequest>(
        AuthenticatorGetInfoRequest::class.java,
        emptyList()
    )