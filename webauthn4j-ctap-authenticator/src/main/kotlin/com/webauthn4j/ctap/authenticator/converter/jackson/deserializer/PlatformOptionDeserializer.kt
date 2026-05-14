package com.webauthn4j.ctap.authenticator.converter.jackson.deserializer

import tools.jackson.core.JsonParser
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.PlatformOption
import com.webauthn4j.ctap.core.data.options.PlatformOption.Companion.create
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