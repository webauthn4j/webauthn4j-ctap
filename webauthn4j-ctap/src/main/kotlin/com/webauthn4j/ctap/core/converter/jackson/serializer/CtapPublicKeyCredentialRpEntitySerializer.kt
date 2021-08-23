package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity

class CtapPublicKeyCredentialRpEntitySerializer :
    AbstractCtapCanonicalCborSerializer<CtapPublicKeyCredentialRpEntity>(
        CtapPublicKeyCredentialRpEntity::class.java, listOf(
            FieldSerializationRule("id", CtapPublicKeyCredentialRpEntity::id),
            FieldSerializationRule("name", CtapPublicKeyCredentialRpEntity::name)
        )
    )
