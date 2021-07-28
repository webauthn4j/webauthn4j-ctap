package com.webauthn4j.ctap.core.converter.jackson.deserializer

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.authenticator.options.ClientPINOption
import com.webauthn4j.ctap.authenticator.options.PlatformOption
import com.webauthn4j.ctap.authenticator.options.PlatformOption.Companion.create
import java.io.IOException

class PlatformOptionDeserializer : StdDeserializer<PlatformOption?>(ClientPINOption::class.java) {
    override fun getNullValue(ctxt: DeserializationContext): PlatformOption? {
        return create(null)
    }

    @Throws(IOException::class)
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): PlatformOption? {
        return create(p.booleanValue)
    }
}