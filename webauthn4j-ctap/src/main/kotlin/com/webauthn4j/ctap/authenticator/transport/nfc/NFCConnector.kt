package com.webauthn4j.ctap.authenticator.transport.nfc

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.authenticator.transport.apdu.CTAPAPDUProcessor
import com.webauthn4j.ctap.authenticator.transport.apdu.CommandAPDUProcessor
import com.webauthn4j.ctap.authenticator.transport.apdu.U2FAPDUProcessor
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * NFC Transport Binding Connector
 */
@Suppress("MemberVisibilityCanBePrivate")
class NFCConnector(
    transactionManager: TransactionManager,
    objectConverter: ObjectConverter
) {

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
        internal const val UNEXPECTED_EXCEPTION_MESSAGE = "Unexpected exception is thrown while processing commandAPDU"
    }

    private val logger = LoggerFactory.getLogger(NFCConnector::class.java)

    internal val selectCommandAPDUProcessor = SelectCommandAPDUProcessor()
    internal val deselectCommandAPDUProcessor = DeselectCommandAPDUProcessor()

    internal val ctapAPDUProcessor = CTAPAPDUProcessor(transactionManager, objectConverter)
    internal val u2fAPDUProcessor = U2FAPDUProcessor(transactionManager)


    private val commandAPDUProcessors: List<CommandAPDUProcessor> = listOf(
        ctapAPDUProcessor,
        u2fAPDUProcessor
    )

    private var aidSelected = false

    suspend fun handleCommandAPDU(commandAPDU: CommandAPDU): ResponseAPDU {
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
            return U2FStatusCode.CLA_NOT_SUPPORTED.toResponseAPDU()
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
            ctapAPDUProcessor.clear()
            u2fAPDUProcessor.clear()
            val response = if (Arrays.equals(command.dataIn, FIDO_AID)) {
                val data = "FIDO_2_0".toByteArray(StandardCharsets.US_ASCII)
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
            ctapAPDUProcessor.clear()
            u2fAPDUProcessor.clear()
            val response = ResponseAPDU(null, 0x09.toByte(), 0x00.toByte())
            aidSelected = false
            return response
        }
    }




}