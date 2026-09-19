package com.webauthn4j.ctap.authenticator.transport.usbip.endpoint

import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.SubmitRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.TransferDirection
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock

class InterruptEndpointTest {

    @Test
    fun `interrupt OUT reports the number of consumed request bytes`() {
        val endpoint = InterruptEndpoint(mock<HIDTransport>())
        val request = SubmitRequest(
            seqnum = 1,
            devid = 2,
            direction = TransferDirection.OUT,
            ep = InterruptEndpoint.EP_NUMBER,
            transferFlags = 0,
            transferBufferLength = 64,
            startFrame = 0,
            numberOfPackets = 0,
            interval = 0,
            setup = SubmitRequest.Setup(0, 0, 0, 0, 0),
            transferBuffer = ByteArray(64),
        )

        val response = endpoint.process(request)

        assertThat(response.actualLength).isEqualTo(64)
        assertThat(response.transferBuffer).isEmpty()
    }
}
