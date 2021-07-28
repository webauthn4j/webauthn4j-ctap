package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoRequest

class AuthenticatorGetInfoCommandSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetInfoRequest>(
        AuthenticatorGetInfoRequest::class.java,
        emptyList()
    )