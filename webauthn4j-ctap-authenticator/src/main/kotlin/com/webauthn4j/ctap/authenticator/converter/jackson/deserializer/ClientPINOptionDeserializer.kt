package com.webauthn4j.ctap.authenticator.converter.jackson.deserializer

import tools.jackson.core.JsonParser
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.ClientPINOption.Companion.create
import java.io.IOException

class ClientPINOptionDeserializer : StdDeserializer<ClientPINOption?>(ClientPINOption::class.java) {
    override fun getNullValue(ctxt: DeserializationContext): ClientPINOption? {
        return create(null)
    }

    @Throws(IOException::class)
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): ClientPINOption? {
        return create(p.booleanValue)
    }
}
