package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorResetResponseData

class AuthenticatorResetResponseDataSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorResetResponseData>(
        AuthenticatorResetResponseData::class.java,
        emptyList()
    )
