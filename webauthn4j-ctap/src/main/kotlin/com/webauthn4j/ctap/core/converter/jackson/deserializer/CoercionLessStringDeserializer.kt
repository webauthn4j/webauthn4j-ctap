package com.webauthn4j.ctap.core.converter.jackson.deserializer

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.deser.std.StringDeserializer
import com.fasterxml.jackson.databind.exc.MismatchedInputException
import java.io.IOException
import java.text.MessageFormat

/**
 * To be removed when https://github.com/FasterXML/jackson-databind/issues/3013 is resolved
 */
class CoercionLessStringDeserializer : StringDeserializer() {
    @Throws(IOException::class)
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext?): String {
        if (p.currentToken != JsonToken.VALUE_STRING) {
            val message: String = MessageFormat.format("Cannot coerce {0} to String value", p.currentToken)
            throw MismatchedInputException.from(p, String::class.java, message)
        }
        return super.deserialize(p, ctxt)
    }
}
