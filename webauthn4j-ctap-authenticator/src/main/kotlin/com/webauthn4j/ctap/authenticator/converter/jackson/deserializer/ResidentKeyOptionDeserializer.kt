package com.webauthn4j.ctap.authenticator.converter.jackson.deserializer

import tools.jackson.core.JsonParser
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption.Companion.create
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