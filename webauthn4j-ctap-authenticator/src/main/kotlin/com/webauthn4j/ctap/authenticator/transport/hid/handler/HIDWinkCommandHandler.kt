package com.webauthn4j.ctap.authenticator.transport.hid.handler

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.core.data.hid.HIDWINKRequestMessage
import com.webauthn4j.ctap.core.data.hid.HIDWINKResponseMessage

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-wink">8.1.9.2.1. CTAPHID_WINK</a>
//spec| The wink command performs a vendor-defined action that provides some visual or audible
//spec| identification a particular authenticator. A typical implementation will do a short burst of
//spec| flashes with a LED or something similar.
class HIDWinkCommandHandler(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession
) {

    suspend fun handle(hidMessage: HIDWINKRequestMessage): HIDWINKResponseMessage {
        ctapAuthenticatorSession.wink()
        return HIDWINKResponseMessage(hidMessage.channelId)
    }
}
