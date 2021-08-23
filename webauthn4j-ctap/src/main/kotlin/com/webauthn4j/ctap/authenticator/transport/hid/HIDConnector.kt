package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.authenticator.transport.apdu.U2FAPDUProcessor
import com.webauthn4j.ctap.core.converter.CtapRequestConverter
import com.webauthn4j.ctap.core.converter.CtapResponseConverter
import com.webauthn4j.ctap.core.converter.HIDPacketConverter
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.U2FStatusCode
import com.webauthn4j.ctap.core.data.hid.*
import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.MAX_PACKET_SIZE
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import com.webauthn4j.util.HexUtil
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import kotlin.experimental.or

class HIDConnector(
    private val transactionManager: TransactionManager,
    objectConverter: ObjectConverter
) {

    companion object {
        private const val KEEPALIVE_INTERVAL = 100L
        private const val HID_PROTOCOL_VERSION_NUMBER: Byte = 2
        private const val MAJOR_DEVICE_VERSION_NUMBER: Byte = 0
        private const val MINOR_DEVICE_VERSION_NUMBER: Byte = 1
        private const val BUILD_DEVICE_VERSION_NUMBER: Byte = 0
        private val CAPABILITIES =
            HIDCapability((HIDCapability.CBOR.value or HIDCapability.NMSG.value))
    }

    private val logger = LoggerFactory.getLogger(HIDConnector::class.java)

    private val ctapRequestConverter = CtapRequestConverter(objectConverter)
    private val ctapResponseConverter = CtapResponseConverter(objectConverter)

    private val u2fAPDUProcessor = U2FAPDUProcessor(transactionManager)

    private val hidPacketConverter = HIDPacketConverter()
    private val hidChannels: MutableMap<HIDChannelId, HIDChannel> = HashMap()
    private var lastAllocatedChannelId: HIDChannelId = HIDChannelId(0)

    private val u2fConfirmationWorker = newSingleThreadContext("u2f-confirmation-worker")

    suspend fun handle(bytes: ByteArray, hidPacketHandler: HIDPacketHandler) {
        try {
            val packetOffset = when (bytes.size) { //TODO: respect reportIdIncluded
                MAX_PACKET_SIZE -> 0
                MAX_PACKET_SIZE + 1 -> 1
                else -> throw IllegalStateException("Unexpected bytes size")
            }
            val packetBytes = bytes.copyOfRange(packetOffset, bytes.size)


            val hidPacket = hidPacketConverter.convert(packetBytes)
            logger.debug("CTAP Request HID Packet: {}", hidPacket.toString())

            var hidChannel = hidChannels[hidPacket.channelId]
            if (hidChannel == null) {
                hidChannel = HIDChannel(hidPacket.channelId)
                hidChannels[hidPacket.channelId] = hidChannel
            }
            hidChannel.handlePacket(hidPacket) {
                logger.debug("CTAP Response HID Packet: {}", it.toString())
                val responseBytes = hidPacketConverter.convert(it)
                hidPacketHandler.onResponse(responseBytes)
            }
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown while processing HID packet", e)
//            TODO()
        }
    }

    private fun allocateNewChannelId(): HIDChannelId {
        lastAllocatedChannelId = lastAllocatedChannelId.next()
        return lastAllocatedChannelId
    }

    private inner class HIDChannel(private val channelId: HIDChannelId) {

        private val hidRequestMessageBuilder = HIDRequestMessageBuilder()

        private val hidKeepAliveWorker = newSingleThreadContext("hid-keepalive-worker-" + HexUtil.encodeToString(channelId.value))

        suspend fun handlePacket(
            hidPacket: HIDPacket,
            responseCallback: ResponseCallback<HIDPacket>
        ) {
            when (hidPacket) {
                is HIDInitializationPacket -> hidRequestMessageBuilder.initialize(hidPacket)
                is HIDContinuationPacket -> hidRequestMessageBuilder.append(hidPacket)
                else -> throw IllegalStateException("Unknown HIDPacket subclass")
            }
            if (hidRequestMessageBuilder.isCompleted) {
                val hidMessage = hidRequestMessageBuilder.build()
                hidRequestMessageBuilder.clear()
                try {
                    handleMessage(hidMessage) {
                        it.toHIDPackets().forEach { parameter ->
                            responseCallback.onResponse(parameter)
                        }
                    }
                } catch (e: RuntimeException) {
                    logger.error("Unexpected exception is thrown while processing HID message", e)
                    HIDERRORResponseMessage(hidMessage.channelId, HIDErrorCode.OTHER).toHIDPackets()
                        .forEach { parameter ->
                            responseCallback.onResponse(parameter)
                        }
                }
            }
        }

        suspend fun handleMessage(
            hidMessage: HIDMessage,
            responseCallback: ResponseCallback<HIDResponseMessage>
        ) {
            logger.debug("CTAP Request HID Message: {}", hidMessage.toString())
            when (hidMessage.command) {
                HIDCommand.CTAPHID_MSG -> handleMsg(hidMessage as HIDMSGRequestMessage) {
                    logger.debug("CTAP Response HID Message: {}", it.toString())
                    responseCallback.onResponse(it)
                }
                HIDCommand.CTAPHID_CBOR -> handleCbor(hidMessage as HIDCBORRequestMessage) {
                    logger.debug("CTAP Response HID Message: {}", it.toString())
                    responseCallback.onResponse(it)
                }
                HIDCommand.CTAPHID_INIT -> handleInit(hidMessage as HIDINITRequestMessage) {
                    logger.debug("CTAP Response HID Message: {}", it.toString())
                    responseCallback.onResponse(it)
                }
                HIDCommand.CTAPHID_PING -> handlePing(hidMessage as HIDPINGRequestMessage) {
                    logger.debug("CTAP Response HID Message: {}", it.toString())
                    responseCallback.onResponse(it)
                }
                HIDCommand.CTAPHID_CANCEL -> handleCancel(hidMessage as HIDCANCELRequestMessage)
                HIDCommand.CTAPHID_WINK -> handleWink(hidMessage as HIDWINKRequestMessage) {
                    logger.debug("CTAP Response HID Message: {}", it.toString())
                    responseCallback.onResponse(it)
                }
                HIDCommand.CTAPHID_LOCK -> handleLock(hidMessage as HIDLOCKRequestMessage) {
                    logger.debug("CTAP Response HID Message: {}", it.toString())
                    responseCallback.onResponse(it)
                }
                else -> throw IllegalArgumentException("%s is not supported".format(hidMessage.command))
            }
        }

        private var u2fConfirmationStatus: Deferred<HIDMSGResponseMessage>? = null
        private var activeRequest: HIDMSGRequestMessage? = null

        private suspend fun handleMsg(
            hidMessage: HIDMSGRequestMessage,
            responseCallback: ResponseCallback<HIDResponseMessage>
        ) {
            coroutineScope {

                val conditionNotSatisfiedMessage = HIDMSGResponseMessage(hidMessage.channelId, ResponseAPDU(U2FStatusCode.CONDITION_NOT_SATISFIED.sw1, U2FStatusCode.CONDITION_NOT_SATISFIED.sw2))

                u2fConfirmationStatus.let {
                    when {
                        it == null -> {
                            resetU2FConfirmationStatus(hidMessage)
                            responseCallback.onResponse(conditionNotSatisfiedMessage)
                        }
                        it.isCompleted -> {
                            if(hidMessage == activeRequest){
                                u2fConfirmationStatus = null
                                activeRequest = null
                                responseCallback.onResponse(it.await())
                            }
                            else{
                                resetU2FConfirmationStatus(hidMessage)
                                responseCallback.onResponse(conditionNotSatisfiedMessage)
                            }
                        }
                        it.isCancelled -> {
                            resetU2FConfirmationStatus(hidMessage)
                            responseCallback.onResponse(conditionNotSatisfiedMessage)
                        }
                        it.isActive -> {
                            delay(KEEPALIVE_INTERVAL)
                            responseCallback.onResponse(conditionNotSatisfiedMessage)
                        }
                        else -> throw IllegalStateException()
                    }
                }
            }
        }

        private suspend fun resetU2FConfirmationStatus(hidMessage: HIDMSGRequestMessage){
            u2fConfirmationStatus= CoroutineScope(u2fConfirmationWorker).async {
                val responseAPDU = u2fAPDUProcessor.process(hidMessage.commandAPDU)
                HIDMSGResponseMessage(hidMessage.channelId, responseAPDU)
            }
            activeRequest = hidMessage
        }

        private suspend fun handleInit(
            hidMessage: HIDINITRequestMessage,
            responseCallback: ResponseCallback<HIDResponseMessage>
        ) {

            val responseMessage = when (val channelId = hidMessage.channelId) {
                HIDChannelId.BROADCAST -> {
                    val newChannelId = allocateNewChannelId()
                    val nonce = hidMessage.nonce
                    HIDINITResponseMessage(
                        channelId,
                        nonce,
                        newChannelId,
                        HID_PROTOCOL_VERSION_NUMBER,
                        MAJOR_DEVICE_VERSION_NUMBER,
                        MINOR_DEVICE_VERSION_NUMBER,
                        BUILD_DEVICE_VERSION_NUMBER,
                        CAPABILITIES
                    )
                }
                else -> {
                    hidChannels.remove(channelId)
                    val nonce = hidMessage.nonce
                    HIDINITResponseMessage(
                        channelId,
                        nonce,
                        channelId,
                        HID_PROTOCOL_VERSION_NUMBER,
                        MAJOR_DEVICE_VERSION_NUMBER,
                        MINOR_DEVICE_VERSION_NUMBER,
                        BUILD_DEVICE_VERSION_NUMBER,
                        CAPABILITIES
                    )
                }
            }
            responseCallback.onResponse(responseMessage)
        }

        private suspend fun handleCbor(
            hidMessage: HIDCBORRequestMessage,
            responseCallback: ResponseCallback<HIDResponseMessage>
        ) {
            coroutineScope {
                val keepAliveJob = launch(hidKeepAliveWorker) {
                    while (true) {
                        val keepAliveMessage = HIDKEEPALIVEResponseMessage(
                            hidMessage.channelId,
                            HIDStatusCode.PROCESSING
                        ) //TODO:StatusCodeを正しく返却できるように
                        responseCallback.onResponse(keepAliveMessage)
                        delay(KEEPALIVE_INTERVAL)
                    }
                }
                val ctapCommand = ctapRequestConverter.convert(hidMessage.data)
                var ctapResponse: CtapResponse
                withContext(Dispatchers.Default) {
                    ctapResponse = transactionManager.invokeCommand(ctapCommand)
                }
                val cbor = ctapResponseConverter.convertToResponseDataBytes(ctapResponse)
                val responseMessage =
                    HIDCBORResponseMessage(hidMessage.channelId, ctapResponse.statusCode, cbor)
                keepAliveJob.cancelAndJoin() // keepAlive must be finished before sending response packets
                responseCallback.onResponse(responseMessage)
            }
        }

        private suspend fun handlePing(
            hidMessage: HIDPINGRequestMessage,
            responseCallback: ResponseCallback<HIDResponseMessage>
        ) {
            responseCallback.onResponse(
                HIDPINGResponseMessage(
                    hidMessage.channelId,
                    hidMessage.data
                )
            )
        }

        private suspend fun handleCancel(hidMessage: HIDCANCELRequestMessage) {
            transactionManager.cancelOnGoingTransaction()
        }

        private fun handleWink(
            hidMessage: HIDWINKRequestMessage,
            responseCallback: ResponseCallback<HIDWINKResponseMessage>
        ) {
            //TODO: wink
            responseCallback.onResponse(HIDWINKResponseMessage(hidMessage.channelId))
        }

        private fun handleLock(
            hidMessage: HIDLOCKRequestMessage,
            responseCallback: ResponseCallback<HIDLOCKResponseMessage>
        ) {
            val seconds = hidMessage.seconds
            //transactionManager.lock(seconds) //TODO
            responseCallback.onResponse(HIDLOCKResponseMessage(hidMessage.channelId))
        }

    }

    private fun interface ResponseCallback<T> {
        fun onResponse(response: T)
    }

}