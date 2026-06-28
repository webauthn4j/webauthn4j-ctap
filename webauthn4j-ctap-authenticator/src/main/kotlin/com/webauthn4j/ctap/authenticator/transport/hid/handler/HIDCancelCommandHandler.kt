package com.webauthn4j.ctap.authenticator.transport.hid.handler

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-cancel">8.1.9.1.5. CTAPHID_CANCEL</a>
//spec| Cancel any outstanding requests on this CID. If there is an outstanding request that can be
//spec| cancelled, the authenticator MUST cancel it and that cancelled request will reply with the error
//spec| CTAP2_ERR_KEEPALIVE_CANCEL.
//spec| Whether a request was cancelled or not, the authenticator MUST NOT reply to the CTAPHID_CANCEL
//spec| message itself.
class HIDCancelCommandHandler(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession
) {

    fun handle() {
        ctapAuthenticatorSession.cancelOnGoingTransaction()
    }
}
