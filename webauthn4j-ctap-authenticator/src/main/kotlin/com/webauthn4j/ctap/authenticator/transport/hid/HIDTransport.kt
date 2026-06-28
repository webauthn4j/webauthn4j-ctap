package com.webauthn4j.ctap.authenticator.transport.hid

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.transport.Transport
import com.webauthn4j.ctap.authenticator.transport.hid.handler.*
import com.webauthn4j.ctap.authenticator.transport.nfc.apdu.U2FAPDUProcessor
import com.webauthn4j.ctap.core.converter.CtapRequestConverter
import com.webauthn4j.ctap.core.converter.CtapResponseConverter
import com.webauthn4j.ctap.core.converter.HIDPacketConverter
import com.webauthn4j.ctap.core.data.hid.*
import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.MAX_PACKET_SIZE
import com.webauthn4j.util.HexUtil
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import java.security.SecureRandom

// @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-discovery">8.1. USB Human Interface Device (USB HID)</a>
class HIDTransport(ctapAuthenticator: CtapAuthenticator) : Transport {

    companion object {
        private const val CTAP_REQUEST_HID_PACKET_LOGGING_TEMPLATE = "CTAP Request HID Packet: {}"
        private const val CTAP_RESPONSE_HID_PACKET_LOGGING_TEMPLATE = "CTAP Response HID Packet: {}"
        private const val CTAP_REQUEST_HID_MESSAGE_LOGGING_TEMPLATE = "CTAP Request HID Message: {}"
        private const val CTAP_RESPONSE_HID_MESSAGE_LOGGING_TEMPLATE = "CTAP Request HID Message: {}"
    }

    private val logger = LoggerFactory.getLogger(HIDTransport::class.java)

    private var ctapAuthenticatorSession: CtapAuthenticatorSession = ctapAuthenticator.createSession() //TODO: revisit

    private val u2fAPDUProcessor = U2FAPDUProcessor().also { it.onConnect(ctapAuthenticatorSession) }

    private val hidPacketConverter = HIDPacketConverter()
    private val hidChannels: MutableMap<HIDChannelId, HIDChannel> = HashMap()
    private val secureRandom = SecureRandom()

    //spec| The application channel that manages to get through the first initialization packet when the device
    //spec| is in idle state will keep the device locked for other channels until the last packet of the response
    //spec| message has been received or the transaction is aborted.
    @Volatile
    private var activeTransactionChannelId: HIDChannelId? = null

    private val lockState = HIDLockCommandHandler.LockState()

    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
    private val u2fConfirmationWorker = newSingleThreadContext("u2f-confirmation-worker")

    private val initHandler = HIDInitCommandHandler(object : HIDInitCommandHandler.ChannelAllocator {
        override fun allocateChannel(): HIDChannelId {
            val id = allocateNewChannelId()
            hidChannels[id] = createChannel(id)
            return id
        }
        override fun resyncChannel(channelId: HIDChannelId) {
            hidChannels.remove(channelId)
            hidChannels[channelId] = createChannel(channelId)
        }
    })
    private val pingHandler = HIDPingCommandHandler()
    private val cancelHandler = HIDCancelCommandHandler(ctapAuthenticatorSession)
    private val winkHandler = HIDWinkCommandHandler(ctapAuthenticatorSession)
    private val lockHandler = HIDLockCommandHandler(lockState)
    private val cborHandler = HIDCborCommandHandler(
        CtapRequestConverter(ctapAuthenticator.objectConverter),
        CtapResponseConverter(ctapAuthenticator.objectConverter),
        ctapAuthenticatorSession,
        newSingleThreadContext("hid-cbor-keepalive-worker")
    )

    private fun sendError(channelId: HIDChannelId, errorCode: HIDErrorCode, hidPacketHandler: HIDPacketHandler) {
        HIDERRORResponseMessage(channelId, errorCode).toHIDPackets()
            .forEach {
                logger.debug(CTAP_RESPONSE_HID_PACKET_LOGGING_TEMPLATE, it.toString())
                hidPacketHandler.onResponse(it.toBytes())
            }
    }

    suspend fun onHIDDataReceived(bytes: ByteArray, hidPacketHandler: HIDPacketHandler) {
        try {
            val packetOffset = when (bytes.size) {
                MAX_PACKET_SIZE -> 0
                MAX_PACKET_SIZE + 1 -> 1
                else -> throw IllegalStateException("Unexpected bytes size")
            }
            val packetBytes = bytes.copyOfRange(packetOffset, bytes.size)

            val hidPacket = hidPacketConverter.convert(packetBytes)
            try {
                logger.debug(CTAP_REQUEST_HID_PACKET_LOGGING_TEMPLATE, hidPacket.toString())
                val channelId = hidPacket.channelId

                //spec| Channel ID 0 is reserved and 0xffffffff is reserved for broadcast commands,
                //spec| i.e. at the time of channel allocation.
                if (channelId == HIDChannelId.BROADCAST) {
                    if (hidPacket !is HIDInitializationPacket || hidPacket.command != HIDCommand.CTAPHID_INIT) {
                        sendError(channelId, HIDErrorCode.INVALID_CHANNEL, hidPacketHandler)
                        return
                    }
                    val tempChannel = createChannel(channelId)
                    tempChannel.handlePacket(hidPacket) { responsePacket ->
                        logger.debug(CTAP_RESPONSE_HID_PACKET_LOGGING_TEMPLATE, responsePacket.toString())
                        hidPacketHandler.onResponse(hidPacketConverter.convert(responsePacket))
                    }
                    return
                }

                //spec| A CTAPHID_CANCEL received while no CTAPHID_CBOR request is being processed,
                //spec| or on a non-active CID SHALL be ignored by the authenticator.
                val isCancelCommand = hidPacket is HIDInitializationPacket
                        && hidPacket.command == HIDCommand.CTAPHID_CANCEL

                var hidChannel = hidChannels[channelId]
                if (hidChannel == null) {
                    if (hidPacket is HIDContinuationPacket) {
                        //spec| Spurious continuation packets appearing without a prior initialization packet will be ignored.
                        logger.debug("Unexpected continuation packet on unknown channel. Skipped.")
                        return
                    }
                    if (isCancelCommand) return
                    sendError(channelId, HIDErrorCode.INVALID_CHANNEL, hidPacketHandler)
                    return
                }

                //spec| As the CTAPHID_CANCEL command is sent during an ongoing transaction,
                //spec| transaction semantics do not apply.
                if (!isCancelCommand) {
                    //spec| If an application tries to access the device from a different channel while the device
                    //spec| is busy with a transaction, that request will immediately fail with a busy-error message
                    //spec| sent to the requesting channel.
                    if (hidPacket is HIDInitializationPacket) {
                        val activeChannel = activeTransactionChannelId
                        if (activeChannel != null && activeChannel != channelId) {
                            sendError(channelId, HIDErrorCode.CHANNEL_BUSY, hidPacketHandler)
                            return
                        }
                    }

                    //spec| As long as the lock is active, any other channel trying to send a message will fail.
                    if (lockState.isActive() && lockState.ownerChannelId != channelId) {
                        sendError(channelId, HIDErrorCode.LOCK_REQUIRED, hidPacketHandler)
                        return
                    }
                }

                hidChannel.handlePacket(hidPacket) { responsePacket ->
                    logger.debug(CTAP_RESPONSE_HID_PACKET_LOGGING_TEMPLATE, responsePacket.toString())
                    hidPacketHandler.onResponse(hidPacketConverter.convert(responsePacket))
                }
            } catch (e: HIDProtocolException) {
                logger.warn("HID protocol error: {}", e.message)
                sendError(hidPacket.channelId, e.errorCode, hidPacketHandler)
            } catch (e: RuntimeException) {
                logger.error("Unexpected exception is thrown while processing HID packet", e)
                sendError(hidPacket.channelId, HIDErrorCode.OTHER, hidPacketHandler)
            }
        } catch (e: RuntimeException) {
            logger.error("Unexpected exception is thrown while processing HID packet", e)
        }
    }

    private fun allocateNewChannelId(): HIDChannelId {
        while (true) {
            val bytes = ByteArray(4)
            secureRandom.nextBytes(bytes)
            val id = HIDChannelId(bytes)
            if (id != HIDChannelId.BROADCAST && !hidChannels.containsKey(id)) {
                return id
            }
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
    private fun createChannel(channelId: HIDChannelId): HIDChannel {
        val keepAliveWorker = newSingleThreadContext("hid-keepalive-worker-" + HexUtil.encodeToString(channelId.value))
        val msgHandler = HIDMsgCommandHandler(u2fAPDUProcessor, u2fConfirmationWorker)
        val perChannelCborHandler = HIDCborCommandHandler(
            CtapRequestConverter(ctapAuthenticatorSession.objectConverter),
            CtapResponseConverter(ctapAuthenticatorSession.objectConverter),
            ctapAuthenticatorSession,
            keepAliveWorker
        )
        return HIDChannel(
            channelId = channelId,
            activeTransactionChannelIdSetter = { activeTransactionChannelId = it },
            initHandler = initHandler,
            cborHandler = perChannelCborHandler,
            msgHandler = msgHandler,
            pingHandler = pingHandler,
            cancelHandler = cancelHandler,
            winkHandler = winkHandler,
            lockHandler = lockHandler
        )
    }

    private fun interface ResponseCallback<T> {
        fun onResponse(response: T)
    }

}
