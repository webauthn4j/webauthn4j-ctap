package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity

class CtapPublicKeyCredentialUserEntitySerializer :
    AbstractCtapCanonicalCborSerializer<CtapPublicKeyCredentialUserEntity>(
        CtapPublicKeyCredentialUserEntity::class.java, listOf(
            FieldSerializationRule("id", CtapPublicKeyCredentialUserEntity::id),
            FieldSerializationRule("icon", CtapPublicKeyCredentialUserEntity::icon),
            FieldSerializationRule("name", CtapPublicKeyCredentialUserEntity::name),
            FieldSerializationRule("displayName", CtapPublicKeyCredentialUserEntity::displayName)
        )
    )
