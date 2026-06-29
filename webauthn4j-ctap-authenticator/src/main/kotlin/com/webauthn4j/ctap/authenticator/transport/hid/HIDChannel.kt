package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.ctap.authenticator.transport.hid.handler.*
import com.webauthn4j.ctap.core.data.hid.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import org.slf4j.LoggerFactory

class HIDChannel(
    private val channelId: HIDChannelId,
    private val scope: CoroutineScope,
    private val activeTransactionChannelIdSetter: (HIDChannelId?) -> Unit,
    private val commandTimeSetter: (Long) -> Unit,
    private val initHandler: HIDInitCommandHandler,
    private val cborHandler: HIDCborCommandHandler,
    private val msgHandler: HIDMsgCommandHandler,
    private val pingHandler: HIDPingCommandHandler,
    private val cancelHandler: HIDCancelCommandHandler,
    private val winkHandler: HIDWinkCommandHandler,
    private val lockHandler: HIDLockCommandHandler
) {

    private val logger = LoggerFactory.getLogger(HIDChannel::class.java)
    private val hidRequestMessageBuilder = HIDRequestMessageBuilder()
    private var cborCompletion: CompletableDeferred<Unit>? = null

    suspend fun handlePacket(
        hidPacket: HIDPacket,
        responseCallback: (HIDPacket) -> Unit
    ) {
        //spec| A transaction has to be completed within a specified period of time to prevent a stalling
        //spec| application to cause the device to be completely locked out for access by other applications.
        if (hidPacket is HIDInitializationPacket && hidRequestMessageBuilder.isTimedOut) {
            logger.debug("Message assembly timed out, resetting builder")
            hidRequestMessageBuilder.clear()
        }

        when (hidPacket) {
            is HIDInitializationPacket -> {
                activeTransactionChannelIdSetter(channelId)
                hidRequestMessageBuilder.initialize(hidPacket)
            }
            is HIDContinuationPacket -> {
                if (hidRequestMessageBuilder.isTimedOut) {
                    hidRequestMessageBuilder.clear()
                    activeTransactionChannelIdSetter(null)
                    throw HIDProtocolException(HIDErrorCode.MSG_TIMEOUT, "Message assembly timed out")
                }
                hidRequestMessageBuilder.append(hidPacket)
            }
            else -> throw HIDProtocolException(HIDErrorCode.OTHER, "Unknown HIDPacket subclass")
        }
        if (hidRequestMessageBuilder.isCompleted) {
            val hidMessage = hidRequestMessageBuilder.build()
            hidRequestMessageBuilder.clear()
            try {
                logger.debug("CTAP Request HID Message: {}", hidMessage)
                handleMessage(hidMessage) {
                    it.toHIDPackets().forEach { packet -> responseCallback(packet) }
                }
            } catch (e: HIDProtocolException) {
                activeTransactionChannelIdSetter(null)
                throw e
            } catch (e: RuntimeException) {
                logger.error("Unexpected exception is thrown while processing HID message", e)
                HIDERRORResponseMessage(hidMessage.channelId, HIDErrorCode.OTHER).toHIDPackets()
                    .forEach { packet -> responseCallback(packet) }
                activeTransactionChannelIdSetter(null)
            }
        }
    }

    private suspend fun handleMessage(
        hidMessage: HIDMessage,
        responseCallback: (HIDResponseMessage) -> Unit
    ) {
        when (hidMessage.command) {
            HIDCommand.CTAPHID_MSG -> {
                msgHandler.handle(hidMessage as HIDMSGRequestMessage) {
                    logger.debug("CTAP Response HID Message: {}", it)
                    responseCallback(it)
                }
                activeTransactionChannelIdSetter(null)
            }
            HIDCommand.CTAPHID_CBOR -> {
                commandTimeSetter(System.currentTimeMillis())
                cborCompletion = cborHandler.handle(scope, hidMessage as HIDCBORRequestMessage,
                    responseCallback = {
                        logger.debug("CTAP Response HID Message: {}", it)
                        responseCallback(it)
                    },
                    onComplete = {
                        commandTimeSetter(0)
                        activeTransactionChannelIdSetter(null)
                        cborCompletion = null
                    }
                )
            }
            HIDCommand.CTAPHID_CANCEL -> {
                //spec| Cancel any outstanding requests on this CID. If there is an outstanding request that can be
                //spec| cancelled, the authenticator MUST cancel it and that cancelled request will reply with the error
                //spec| CTAP2_ERR_KEEPALIVE_CANCEL.
                //spec| Whether a request was cancelled or not, the authenticator MUST NOT reply to the CTAPHID_CANCEL
                //spec| message itself.
                cancelHandler.handle()
                cborCompletion?.await()
            }
            HIDCommand.CTAPHID_INIT -> {
                val response = initHandler.handle(hidMessage as HIDINITRequestMessage)
                logger.debug("CTAP Response HID Message: {}", response)
                responseCallback(response)
                activeTransactionChannelIdSetter(null)
            }
            HIDCommand.CTAPHID_PING -> {
                val response = pingHandler.handle(hidMessage as HIDPINGRequestMessage)
                logger.debug("CTAP Response HID Message: {}", response)
                responseCallback(response)
                activeTransactionChannelIdSetter(null)
            }
            HIDCommand.CTAPHID_WINK -> {
                val response = winkHandler.handle(hidMessage as HIDWINKRequestMessage)
                logger.debug("CTAP Response HID Message: {}", response)
                responseCallback(response)
                activeTransactionChannelIdSetter(null)
            }
            HIDCommand.CTAPHID_LOCK -> {
                val response = lockHandler.handle(hidMessage as HIDLOCKRequestMessage, channelId)
                logger.debug("CTAP Response HID Message: {}", response)
                responseCallback(response)
                activeTransactionChannelIdSetter(null)
            }
            else -> {
                activeTransactionChannelIdSetter(null)
                throw HIDProtocolException(HIDErrorCode.INVALID_CMD, "%s is not supported".format(hidMessage.command))
            }
        }
    }
}
