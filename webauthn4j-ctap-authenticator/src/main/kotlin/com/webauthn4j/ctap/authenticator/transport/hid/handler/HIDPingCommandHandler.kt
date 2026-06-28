package com.webauthn4j.ctap.authenticator.transport.hid.handler

import com.webauthn4j.ctap.core.data.hid.HIDPINGRequestMessage
import com.webauthn4j.ctap.core.data.hid.HIDPINGResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDResponseMessage

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-ping">8.1.9.1.4. CTAPHID_PING</a>
//spec| Sends a transaction to the device, which immediately echoes the same data back. This command
//spec| is defined to be a uniform function for debugging, latency and performance measurements.
class HIDPingCommandHandler {

    fun handle(hidMessage: HIDPINGRequestMessage): HIDResponseMessage {
        return HIDPINGResponseMessage(hidMessage.channelId, hidMessage.data)
    }
}
