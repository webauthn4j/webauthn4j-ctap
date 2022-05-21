package com.webauthn4j.ctap.authenticator.converter.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.webauthn4j.ctap.authenticator.U2FKeyEnvelope
import com.webauthn4j.ctap.authenticator.converter.jackson.deserializer.*
import com.webauthn4j.ctap.authenticator.converter.jackson.serializer.U2FKeyEnvelopeSerializer
import com.webauthn4j.ctap.core.data.options.*

class CtapAuthenticatorCBORModule : SimpleModule("WebAuthnCBORModule") {
    init {
        this.addSerializer(U2FKeyEnvelope::class.java, U2FKeyEnvelopeSerializer())

        this.addDeserializer(ClientPINOption::class.java, ClientPINOptionDeserializer())
        this.addDeserializer(PlatformOption::class.java, PlatformOptionDeserializer())
        this.addDeserializer(ResidentKeyOption::class.java, ResidentKeyOptionDeserializer())
        this.addDeserializer(UserPresenceOption::class.java, UserPresenceOptionDeserializer())
        this.addDeserializer(UserVerificationOption::class.java, UserVerificationOptionDeserializer())
    }
}