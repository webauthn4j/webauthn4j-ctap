package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorSelectionResponseData

class AuthenticatorSelectionResponseDataSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorSelectionResponseData>(
        AuthenticatorSelectionResponseData::class.java,
        emptyList()
    )
