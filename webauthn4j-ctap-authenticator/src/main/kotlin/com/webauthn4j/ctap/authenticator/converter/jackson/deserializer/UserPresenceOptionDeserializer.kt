package com.webauthn4j.ctap.authenticator.converter.jackson.deserializer

import tools.jackson.core.JsonParser
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.core.data.options.UserPresenceOption
import com.webauthn4j.ctap.core.data.options.UserPresenceOption.Companion.create
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
