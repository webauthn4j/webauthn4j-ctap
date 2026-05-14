package com.webauthn4j.ctap.authenticator.converter.jackson.deserializer

import tools.jackson.core.JsonParser
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption.Companion.create
import java.io.IOException

class UserVerificationOptionDeserializer :
    StdDeserializer<UserVerificationOption?>(UserVerificationOption::class.java) {
    override fun getNullValue(ctxt: DeserializationContext): UserVerificationOption? {
        return create(null)
    }

    @Throws(IOException::class)
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): UserVerificationOption? {
        return create(p.booleanValue)
    }
}
