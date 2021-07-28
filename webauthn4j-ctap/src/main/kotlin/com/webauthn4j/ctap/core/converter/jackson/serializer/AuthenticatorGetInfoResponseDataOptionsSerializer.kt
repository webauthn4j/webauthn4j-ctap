package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData

class AuthenticatorGetInfoResponseDataOptionsSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetInfoResponseData.Options>(AuthenticatorGetInfoResponseData.Options::class.java,
        listOf(
            FieldSerializationRule("plat") { it.plat?.value },
            FieldSerializationRule("rk") { it.rk?.value },
            FieldSerializationRule("clientPin") { it.clientPin?.value },
            FieldSerializationRule("up") { it.up?.value },
            FieldSerializationRule("uv") { it.uv?.value }
        ))
