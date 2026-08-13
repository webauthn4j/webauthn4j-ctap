package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.data.PublicKeyCredentialUserEntity

class PublicKeyCredentialUserEntitySerializer :
    AbstractCtapCanonicalCborSerializer<PublicKeyCredentialUserEntity>(
        PublicKeyCredentialUserEntity::class.java, listOf(
            FieldSerializationRule("id", PublicKeyCredentialUserEntity::getId),
            FieldSerializationRule("name", PublicKeyCredentialUserEntity::getName),
            FieldSerializationRule("displayName", PublicKeyCredentialUserEntity::getDisplayName)
        )
    )
