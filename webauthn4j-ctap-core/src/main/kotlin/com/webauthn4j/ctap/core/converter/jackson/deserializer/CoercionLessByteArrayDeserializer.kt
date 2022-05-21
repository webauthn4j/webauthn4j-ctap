package com.webauthn4j.ctap.core.converter.jackson.deserializer

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.deser.std.PrimitiveArrayDeserializers
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.fasterxml.jackson.databind.exc.MismatchedInputException
import java.text.MessageFormat

class CoercionLessByteArrayDeserializer : StdDeserializer<ByteArray>(StdDeserializer::class.java) {

    override fun deserialize(p: JsonParser, ctxt: DeserializationContext?): ByteArray {
        if (p.currentToken != JsonToken.VALUE_EMBEDDED_OBJECT) {
            val message: String =
                MessageFormat.format("Cannot coerce {0} to ByteArray value", p.currentToken)
            throw MismatchedInputException.from(p, String::class.java, message)
        }
        val deserializer = PrimitiveArrayDeserializers.forType(Byte::class.java)
        return deserializer.deserialize(p, ctxt) as ByteArray
    }
}