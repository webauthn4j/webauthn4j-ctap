package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.authenticator.U2FKeyEnvelope

class U2FKeyEnvelopeSerializer : AbstractCtapCanonicalCborSerializer<U2FKeyEnvelope>(
    U2FKeyEnvelope::class.java, listOf(
        FieldSerializationRule(1, { envelope -> envelope.version.toByte() }),
        FieldSerializationRule(2, U2FKeyEnvelope::keyPair),
        FieldSerializationRule(3, U2FKeyEnvelope::applicationParameter),
        FieldSerializationRule(4, { envelope -> envelope.createdAt.epochSecond })
    )
)
