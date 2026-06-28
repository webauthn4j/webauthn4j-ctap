package com.webauthn4j.ctap.authenticator.transport.hid.handler

import com.webauthn4j.ctap.authenticator.transport.nfc.apdu.U2FAPDUProcessor
import com.webauthn4j.ctap.core.data.U2FStatusCode
import com.webauthn4j.ctap.core.data.hid.HIDMSGRequestMessage
import com.webauthn4j.ctap.core.data.hid.HIDMSGResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDResponseMessage
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlin.coroutines.CoroutineContext

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-msg">8.1.9.1.1. CTAPHID_MSG</a>
//spec| This command sends an encapsulated CTAP1/U2F message to the device. The semantics of the
//spec| data message is defined in the U2F Raw Message Format encoding specification.
class HIDMsgCommandHandler(
    private val u2fAPDUProcessor: U2FAPDUProcessor,
    private val u2fConfirmationWorker: CoroutineContext
) {

    companion object {
        private const val KEEPALIVE_INTERVAL = 100L
    }

    private var u2fConfirmationStatus: Deferred<HIDMSGResponseMessage>? = null
    private var activeRequest: HIDMSGRequestMessage? = null

    suspend fun handle(
        hidMessage: HIDMSGRequestMessage,
        responseCallback: (HIDResponseMessage) -> Unit
    ) {
        coroutineScope {
            val conditionNotSatisfiedMessage = HIDMSGResponseMessage(
                hidMessage.channelId,
                ResponseAPDU(
                    U2FStatusCode.CONDITION_NOT_SATISFIED.sw1,
                    U2FStatusCode.CONDITION_NOT_SATISFIED.sw2
                )
            )

            u2fConfirmationStatus.let {
                when {
                    it == null || it.isCancelled -> {
                        resetU2FConfirmationStatus(hidMessage)
                        responseCallback(conditionNotSatisfiedMessage)
                    }
                    it.isCompleted -> {
                        if (hidMessage == activeRequest) {
                            u2fConfirmationStatus = null
                            activeRequest = null
                            responseCallback(it.await())
                        } else {
                            resetU2FConfirmationStatus(hidMessage)
                            responseCallback(conditionNotSatisfiedMessage)
                        }
                    }
                    it.isActive -> {
                        delay(KEEPALIVE_INTERVAL)
                        responseCallback(conditionNotSatisfiedMessage)
                    }
                    else -> throw IllegalStateException()
                }
            }
        }
    }

    private fun resetU2FConfirmationStatus(hidMessage: HIDMSGRequestMessage) {
        u2fConfirmationStatus = CoroutineScope(u2fConfirmationWorker).async {
            val responseAPDU = u2fAPDUProcessor.process(hidMessage.commandAPDU)
            HIDMSGResponseMessage(hidMessage.channelId, responseAPDU)
        }
        activeRequest = hidMessage
    }
}
