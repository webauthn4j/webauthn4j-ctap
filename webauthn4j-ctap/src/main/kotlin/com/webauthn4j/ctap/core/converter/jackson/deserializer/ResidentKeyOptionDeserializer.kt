package com.webauthn4j.ctap.core.converter.jackson.deserializer

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.authenticator.data.options.ResidentKeyOption
import com.webauthn4j.ctap.authenticator.data.options.ResidentKeyOption.Companion.create
import java.io.IOException

class ResidentKeyOptionDeserializer :
    StdDeserializer<ResidentKeyOption?>(ResidentKeyOption::class.java) {
    override fun getNullValue(ctxt: DeserializationContext): ResidentKeyOption? {
        return create(null)
    }

    @Throws(IOException::class)
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): ResidentKeyOption? {
        return create(p.booleanValue)
    }
}