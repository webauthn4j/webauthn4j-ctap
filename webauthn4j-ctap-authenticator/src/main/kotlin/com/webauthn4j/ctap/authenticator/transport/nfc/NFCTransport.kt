package com.webauthn4j.ctap.authenticator.transport.nfc

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.Transport
import com.webauthn4j.ctap.authenticator.transport.nfc.apdu.CTAPAPDUProcessor
import com.webauthn4j.ctap.authenticator.transport.nfc.apdu.CommandAPDUProcessor
import com.webauthn4j.ctap.authenticator.transport.nfc.apdu.U2FAPDUProcessor
import com.webauthn4j.ctap.core.data.U2FStatusCode
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * NFC Transport Binding
 */
@Suppress("MemberVisibilityCanBePrivate")
class NFCTransport(private val ctapAuthenticator: CtapAuthenticator) : Transport {

    companion object {
        private val FIDO_AID = byteArrayOf(
            0xA0.toByte(),
            0x00.toByte(),
            0x00.toByte(),
            0x06.toByte(),
            0x47.toByte(),
            0x2f.toByte(),
            0x00.toByte(),
            0x01.toByte()
        )
        private const val NFC_CTAP_CONTROL = 0x12.toByte()
        internal const val NFC_CTAP_MSG = 0x10.toByte()
        internal const val UNEXPECTED_EXCEPTION_MESSAGE =
            "Unexpected exception is thrown while processing commandAPDU"
    }

    private val logger = LoggerFactory.getLogger(NFCTransport::class.java)

    internal val selectCommandAPDUProcessor = SelectCommandAPDUProcessor()
    internal val deselectCommandAPDUProcessor = DeselectCommandAPDUProcessor()

    internal val ctapAPDUProcessor: CTAPAPDUProcessor = CTAPAPDUProcessor(ctapAuthenticator.objectConverter)
    internal val u2fAPDUProcessor = U2FAPDUProcessor()


    private val commandAPDUProcessors: List<CommandAPDUProcessor> = listOf(
        ctapAPDUProcessor,
        u2fAPDUProcessor
    )

    private var aidSelected = false

    suspend fun onCommandAPDUReceived(commandAPDU: CommandAPDU): ResponseAPDU {
        try {
            if (selectCommandAPDUProcessor.isTarget(commandAPDU)) {
                return try {
                    selectCommandAPDUProcessor.process(commandAPDU)
                } catch (e: RuntimeException) {
                    logger.error(UNEXPECTED_EXCEPTION_MESSAGE, e)
                    ResponseAPDU.createErrorResponseAPDU()
                }
            }
            if (deselectCommandAPDUProcessor.isTarget(commandAPDU)) {
                return try {
                    deselectCommandAPDUProcessor.process(commandAPDU)
                } catch (e: RuntimeException) {
                    logger.error(UNEXPECTED_EXCEPTION_MESSAGE, e)
                    ResponseAPDU.createErrorResponseAPDU()
                }
            }
            for (commandAPDUProcessor in commandAPDUProcessors) {
                if (commandAPDUProcessor.isTarget(commandAPDU)) {
                    return if (aidSelected) {
                        commandAPDUProcessor.process(commandAPDU)
                    } else {
                        logger.warn("Processing Unexpected APDU command")
                        ResponseAPDU.createErrorResponseAPDU()
                    }
                }
            }
            logger.debug("Processing Unknown APDU command")
            return U2FStatusCode.INS_NOT_SUPPORTED.toResponseAPDU()
        } catch (e: RuntimeException) {
            logger.error(UNEXPECTED_EXCEPTION_MESSAGE, e)
            return ResponseAPDU.createErrorResponseAPDU()
        }
    }

    inner class SelectCommandAPDUProcessor : CommandAPDUProcessor {
        private val logger = LoggerFactory.getLogger(SelectCommandAPDUProcessor::class.java)
        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x00.toByte() && command.ins == 0xA4.toByte() && command.p1 == 0x04.toByte() && command.p2 == 0x00.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            logger.debug("Processing Select APDU command")
            val connection = ctapAuthenticator.createSession()
            ctapAPDUProcessor.onConnect(connection)
            u2fAPDUProcessor.onConnect(connection)
            val response = if (Arrays.equals(command.dataIn, FIDO_AID)) {
                val data = "U2F_V2".toByteArray(StandardCharsets.US_ASCII)
                val sw1 = 0x90.toByte()
                val sw2 = 0x00.toByte()
                ResponseAPDU(data, sw1, sw2)
            } else {
                ResponseAPDU.createErrorResponseAPDU()
            }
            aidSelected = true
            return response
        }
    }

    inner class DeselectCommandAPDUProcessor : CommandAPDUProcessor {
        private val logger = LoggerFactory.getLogger(DeselectCommandAPDUProcessor::class.java)
        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x80.toByte() && command.ins == NFC_CTAP_CONTROL && command.p1 == 0x01.toByte() && command.p2 == 0x00.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            logger.debug("Processing Deselect APDU command")
            ctapAPDUProcessor.onDisconnect()
            u2fAPDUProcessor.onDisconnect()
            val response = ResponseAPDU(null, 0x09.toByte(), 0x00.toByte())
            aidSelected = false
            return response
        }
    }


}