package com.webauthn4j.ctap.core.converter.jackson.serializer

import tools.jackson.core.JsonGenerator
import tools.jackson.databind.SerializationContext
import tools.jackson.databind.jsontype.TypeSerializer
import tools.jackson.databind.ser.std.StdSerializer
import java.io.IOException
import java.security.PublicKey

class PublicKeySerializer : StdSerializer<PublicKey>(PublicKey::class.java) {

    @Throws(IOException::class)
    override fun serialize(value: PublicKey, jsonGenerator: JsonGenerator, serializationContext: SerializationContext) {
        jsonGenerator.writeStartObject()
        jsonGenerator.writeStringProperty("format", value.format)
        jsonGenerator.writeBinaryProperty("encoded", value.encoded)
        jsonGenerator.writeStringProperty("algorithm", value.algorithm)
        jsonGenerator.writeEndObject()
    }

    @Throws(IOException::class)
    override fun serializeWithType(
        value: PublicKey, jsonGenerator: JsonGenerator,
        serializationContext: SerializationContext, typeSerializer: TypeSerializer
    ) {
        serialize(value, jsonGenerator, serializationContext)
    }
}