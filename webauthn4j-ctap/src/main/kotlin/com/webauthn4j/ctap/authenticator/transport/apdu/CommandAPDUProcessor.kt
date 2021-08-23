package com.webauthn4j.ctap.authenticator.transport.apdu

import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU

internal interface CommandAPDUProcessor {
    fun isTarget(command: CommandAPDU): Boolean
    suspend fun process(command: CommandAPDU): ResponseAPDU
}