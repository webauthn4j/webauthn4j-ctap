package com.webauthn4j.ctap.core.converter.jackson.serializer

import tools.jackson.core.JsonGenerator
import tools.jackson.databind.SerializationContext
import tools.jackson.databind.jsontype.TypeSerializer
import tools.jackson.databind.ser.std.StdSerializer
import java.io.IOException
import java.security.PrivateKey

class PrivateKeySerializer : StdSerializer<PrivateKey>(PrivateKey::class.java) {
    @Throws(IOException::class)
    override fun serialize(value: PrivateKey, jsonGenerator: JsonGenerator, serializationContext: SerializationContext) {
        requireNotNull(value.encoded) { "This private key cannot be serialized. It may be backed by external key store like Android KeyStore." }
        jsonGenerator.writeStartObject()
        jsonGenerator.writeStringProperty("format", value.format)
        jsonGenerator.writeBinaryProperty("encoded", value.encoded)
        jsonGenerator.writeStringProperty("algorithm", value.algorithm)
        jsonGenerator.writeEndObject()
    }

    @Throws(IOException::class)
    override fun serializeWithType(
        value: PrivateKey, jsonGenerator: JsonGenerator,
        serializationContext: SerializationContext, typeSerializer: TypeSerializer
    ) {
        serialize(value, jsonGenerator, serializationContext)
    }
}
