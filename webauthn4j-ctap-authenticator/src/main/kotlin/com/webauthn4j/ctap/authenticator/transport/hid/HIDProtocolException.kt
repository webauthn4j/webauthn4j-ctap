package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.ctap.core.data.hid.HIDErrorCode

class HIDProtocolException(val errorCode: HIDErrorCode, message: String) : RuntimeException(message)
