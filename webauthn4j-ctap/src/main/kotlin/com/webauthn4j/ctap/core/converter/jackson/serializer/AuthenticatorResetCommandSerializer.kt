package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorResetRequest

class AuthenticatorResetCommandSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorResetRequest>(
        AuthenticatorResetRequest::class.java,
        emptyList()
    )
