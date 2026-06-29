package com.webauthn4j.ctap.authenticator.transport.hid.handler

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.execution.CtapCommandExecutionException
import com.webauthn4j.ctap.core.converter.CtapRequestConverter
import com.webauthn4j.ctap.core.converter.CtapResponseConverter
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.hid.HIDCBORRequestMessage
import com.webauthn4j.ctap.core.data.hid.HIDCBORResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDKEEPALIVEResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDResponseMessage
import com.webauthn4j.ctap.core.data.hid.HIDStatusCode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.coroutines.CoroutineContext

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-cbor">8.1.9.1.2. CTAPHID_CBOR</a>
//spec| This command sends an encapsulated CTAP CBOR encoded message. The semantics of the data
//spec| message is defined in the CTAP Message encoding specification. Please note that keep-alive
//spec| messages MAY be sent from the device to the client before the response message is returned.
class HIDCborCommandHandler(
    private val ctapRequestConverter: CtapRequestConverter,
    private val ctapResponseConverter: CtapResponseConverter,
    private val ctapAuthenticatorSession: CtapAuthenticatorSession,
    private val keepAliveWorker: CoroutineContext
) {

    companion object {
        //spec| This command code is sent while processing a CTAPHID_MSG. It should be sent at least
        //spec| every 100ms and whenever the status changes.
        private const val KEEPALIVE_INTERVAL = 100L
    }

    suspend fun handle(
        hidMessage: HIDCBORRequestMessage,
        responseCallback: (HIDResponseMessage) -> Unit
    ) {
        try {
            coroutineScope {
                val keepAliveJob = launch(keepAliveWorker) {
                    while (true) {
                        responseCallback(HIDKEEPALIVEResponseMessage(hidMessage.channelId, HIDStatusCode.PROCESSING))
                        delay(KEEPALIVE_INTERVAL)
                    }
                }
                val ctapCommand = ctapRequestConverter.convert(hidMessage.data)
                val ctapResponse: CtapResponse = ctapAuthenticatorSession.invokeCommand(ctapCommand)
                val cbor = ctapResponseConverter.convertToResponseDataBytes(ctapResponse)
                val responseMessage = HIDCBORResponseMessage(hidMessage.channelId, ctapResponse.statusCode, cbor)
                keepAliveJob.cancelAndJoin()
                responseCallback(responseMessage)
            }
        } catch (_: CancellationException) {
            responseCallback(HIDCBORResponseMessage(hidMessage.channelId, CtapStatusCode.CTAP2_ERR_KEEPALIVE_CANCEL, ByteArray(0)))
        } catch (e: CtapCommandExecutionException) {
            responseCallback(HIDCBORResponseMessage(hidMessage.channelId, e.statusCode, ByteArray(0)))
        } catch (_: Exception) {
            responseCallback(HIDCBORResponseMessage(hidMessage.channelId, CtapStatusCode.CTAP1_ERR_OTHER, ByteArray(0)))
        }
    }
}
