package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.jsontype.TypeSerializer
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import java.io.IOException
import java.security.PrivateKey

class PrivateKeySerializer : StdSerializer<PrivateKey>(PrivateKey::class.java) {
    @Throws(IOException::class)
    override fun serialize(value: PrivateKey, gen: JsonGenerator, provider: SerializerProvider) {
        requireNotNull(value.encoded) { "This private key cannot be serialized. It may be backed by external key store like Android KeyStore." }
        gen.writeStartObject()
        gen.writeStringField("format", value.format)
        gen.writeBinaryField("encoded", value.encoded)
        gen.writeStringField("algorithm", value.algorithm)
        gen.writeEndObject()
    }

    @Throws(IOException::class)
    override fun serializeWithType(
        value: PrivateKey, gen: JsonGenerator,
        provider: SerializerProvider, typeSer: TypeSerializer
    ) {
        serialize(value, gen, provider)
    }
}
