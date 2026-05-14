package com.webauthn4j.ctap.core.converter.jackson.deserializer

import tools.jackson.core.JsonParser
import tools.jackson.core.JsonToken
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.deser.std.StdDeserializer
import tools.jackson.databind.exc.MismatchedInputException
import java.text.MessageFormat

class CoercionLessByteArrayDeserializer : StdDeserializer<ByteArray>(ByteArray::class.java) {

    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): ByteArray {
        if (p.currentToken() != JsonToken.VALUE_EMBEDDED_OBJECT) {
            val message: String =
                MessageFormat.format("Cannot coerce {0} to ByteArray value", p.currentToken())
            throw MismatchedInputException.from(p, ByteArray::class.java, message)
        }
        return p.binaryValue
    }
}
