package com.webauthn4j.ctap.authenticator.converter.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.webauthn4j.ctap.authenticator.U2FKeyEnvelope
import com.webauthn4j.ctap.authenticator.converter.jackson.deserializer.ClientPINOptionDeserializer
import com.webauthn4j.ctap.authenticator.converter.jackson.deserializer.PlatformOptionDeserializer
import com.webauthn4j.ctap.authenticator.converter.jackson.deserializer.ResidentKeyOptionDeserializer
import com.webauthn4j.ctap.authenticator.converter.jackson.deserializer.UserPresenceOptionDeserializer
import com.webauthn4j.ctap.authenticator.converter.jackson.deserializer.UserVerificationOptionDeserializer
import com.webauthn4j.ctap.authenticator.converter.jackson.serializer.U2FKeyEnvelopeSerializer
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.PlatformOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.UserPresenceOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption

class CtapAuthenticatorCBORModule : SimpleModule("CtapAuthenticatorCBORModule") {
    init {
        this.addSerializer(U2FKeyEnvelope::class.java, U2FKeyEnvelopeSerializer())

        this.addDeserializer(ClientPINOption::class.java, ClientPINOptionDeserializer())
        this.addDeserializer(PlatformOption::class.java, PlatformOptionDeserializer())
        this.addDeserializer(ResidentKeyOption::class.java, ResidentKeyOptionDeserializer())
        this.addDeserializer(UserPresenceOption::class.java, UserPresenceOptionDeserializer())
        this.addDeserializer(UserVerificationOption::class.java, UserVerificationOptionDeserializer())
    }
}