package com.webauthn4j.ctap.core.converter.jackson.deserializer

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.webauthn4j.ctap.authenticator.options.UserVerificationOption
import com.webauthn4j.ctap.authenticator.options.UserVerificationOption.Companion.create
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
