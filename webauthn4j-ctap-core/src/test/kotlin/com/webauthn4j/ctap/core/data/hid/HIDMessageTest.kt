package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.transport.hid.HIDResponseMessageBuilder
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.data.CtapStatusCode.Companion.CTAP2_OK
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.PlatformOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.UserPresenceOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.attestation.authenticator.AAGUID
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

internal class HIDMessageTest {

    @Test
    fun test() {
        val cbor = ObjectConverter().cborConverter.writeValueAsBytes(
            AuthenticatorGetInfoResponse(
                CTAP2_OK,
                AuthenticatorGetInfoResponseData(
                    listOf("FIDO_2_0"),
                    listOf(),
                    AAGUID(UUID.randomUUID()),
                    AuthenticatorGetInfoResponseData.Options(
                        PlatformOption.CROSS_PLATFORM,
                        ResidentKeyOption.SUPPORTED,
                        ClientPINOption.NOT_SET,
                        UserPresenceOption.SUPPORTED,
                        UserVerificationOption.READY
                    ),
                    1024u,
                    listOf(),
                    null,
                    null,
                    null
                )
            )
        )
        val message = HIDCBORResponseMessage(HIDChannelId(ByteArray(4)), CTAP2_OK, cbor)
        val packets = message.toHIDPackets()
        val builder = HIDResponseMessageBuilder()
        packets.forEach { packet ->
            when (packet) {
                is HIDInitializationPacket -> builder.initialize(packet)
                is HIDContinuationPacket -> {
                    builder.append(packet)
                }
            }
        }
        assertThat(builder.isCompleted).isTrue
        val builtMessage = builder.build()
        assertThat(builtMessage).isEqualTo(message)
    }
}