package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.data.PublicKeyCredentialRpEntity

class PublicKeyCredentialRpEntitySerializer :
    AbstractCtapCanonicalCborSerializer<PublicKeyCredentialRpEntity>(
        PublicKeyCredentialRpEntity::class.java, listOf(
            FieldSerializationRule("id", PublicKeyCredentialRpEntity::getId),
            FieldSerializationRule("name", PublicKeyCredentialRpEntity::getName)
        )
    )
