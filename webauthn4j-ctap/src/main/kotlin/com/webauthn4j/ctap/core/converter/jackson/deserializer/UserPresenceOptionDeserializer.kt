package com.webauthn4j.ctap.core.converter.jackson.deserializer

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.authenticator.data.options.UserPresenceOption
import com.webauthn4j.ctap.authenticator.data.options.UserPresenceOption.Companion.create
import java.io.IOException

class UserPresenceOptionDeserializer :
    StdDeserializer<UserPresenceOption?>(UserPresenceOption::class.java) {
    override fun getNullValue(ctxt: DeserializationContext): UserPresenceOption? {
        return create(null)
    }

    @Throws(IOException::class)
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): UserPresenceOption? {
        return create(p.booleanValue)
    }
}
