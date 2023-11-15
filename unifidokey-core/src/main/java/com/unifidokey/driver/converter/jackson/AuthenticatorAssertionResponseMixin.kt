package com.unifidokey.driver.converter.jackson

import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.unifidokey.driver.converter.jackson.deserializer.json.ByteArraySerializer
import com.unifidokey.driver.converter.jackson.serializer.json.ByteArrayDeserializer

abstract class AuthenticatorAssertionResponseMixin {

    @get:JsonDeserialize(using = ByteArrayDeserializer::class)
    @get:JsonSerialize(using = ByteArraySerializer::class)
    abstract val authenticatorData: String

    @get:JsonDeserialize(using = ByteArrayDeserializer::class)
    @get:JsonSerialize(using = ByteArraySerializer::class)
    abstract val signature: String

    @get:JsonDeserialize(using = ByteArrayDeserializer::class)
    @get:JsonSerialize(using = ByteArraySerializer::class)
    abstract val userHandle: String
}
