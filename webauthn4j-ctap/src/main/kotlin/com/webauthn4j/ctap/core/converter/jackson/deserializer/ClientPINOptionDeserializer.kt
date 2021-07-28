package com.webauthn4j.ctap.core.converter.jackson.deserializer

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.authenticator.options.ClientPINOption
import com.webauthn4j.ctap.authenticator.options.ClientPINOption.Companion.create
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
