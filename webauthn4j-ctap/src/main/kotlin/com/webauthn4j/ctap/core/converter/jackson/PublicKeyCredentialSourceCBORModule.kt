package com.webauthn4j.ctap.core.converter.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.webauthn4j.ctap.core.converter.jackson.deserializer.PrivateKeyDeserializer
import com.webauthn4j.ctap.core.converter.jackson.deserializer.PublicKeyDeserializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.PrivateKeySerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.PublicKeySerializer
import java.security.PrivateKey
import java.security.PublicKey

class PublicKeyCredentialSourceCBORModule : SimpleModule("PublicKeyCredentialSourceCBORModule") {
    init {
        addDeserializer(PrivateKey::class.java, PrivateKeyDeserializer())
        addDeserializer(PublicKey::class.java, PublicKeyDeserializer())
        this.addSerializer(PrivateKey::class.java, PrivateKeySerializer())
        this.addSerializer(PublicKey::class.java, PublicKeySerializer())
    }
}
