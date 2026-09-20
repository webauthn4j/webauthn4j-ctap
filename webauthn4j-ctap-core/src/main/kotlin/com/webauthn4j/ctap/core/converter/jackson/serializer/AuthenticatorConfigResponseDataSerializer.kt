package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorConfigResponseData

class AuthenticatorConfigResponseDataSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorConfigResponseData>(
        AuthenticatorConfigResponseData::class.java,
        emptyList()
    )
