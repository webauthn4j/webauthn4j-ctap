package com.webauthn4j.ctap.authenticator.transport.apdu

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.authenticator.exception.U2FCommandExecutionException
import com.webauthn4j.ctap.core.converter.CtapRequestConverter
import com.webauthn4j.ctap.core.converter.CtapResponseConverter
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.UncheckedIOException
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * NFC Transport Binding Connector
 */
@Suppress("MemberVisibilityCanBePrivate")
class APDUBasedProtocolConnector(
    private val transactionManager: TransactionManager,
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
        private const val NFC_CTAP_MSG = 0x10.toByte()
        private const val UNEXPECTED_EXCEPTION_MESSAGE = "Unexpected exception is thrown while processing commandAPDU"
    }

    private val ctapRequestConverter: CtapRequestConverter = CtapRequestConverter(objectConverter)
    private val ctapResponseConverter: CtapResponseConverter =
        CtapResponseConverter(objectConverter)

    private val logger = LoggerFactory.getLogger(APDUBasedProtocolConnector::class.java)
    private val ctapCommandAPDUQueue: Queue<CommandAPDU> = LinkedList()
    private val ctapResponseQueue = ResponseQueue()
    private val u2fResponseQueue = ResponseQueue()

    internal val selectCommandAPDUProcessor = SelectCommandAPDUProcessor()
    internal val deselectCommandAPDUProcessor = DeselectCommandAPDUProcessor()
    internal val ctapCommandFragmentCommandAPDUProcessor = CtapCommandFragmentCommandAPDUProcessor()
    internal val ctapCommandFinalFragmentCommandAPDUProcessor = CtapRequestFinalFragmentCommandAPDUProcessor()
    internal val ctapContinuationAPDURequestCommandAPDUProcessor = CtapContinuationAPDURequestCommandAPDUProcessor()
    internal val u2fRegisterCommandAPDUProcessor = U2FRegisterCommandAPDUProcessor()
    internal val u2fAuthenticateCommandAPDUProcessor = U2FAuthenticateCommandAPDUProcessor()
    internal val u2fVersionCommandAPDUProcessor = U2FVersionCommandAPDUProcessor()
    internal val u2fContinuationAPDURequestCommandAPDUProcessor = U2FContinuationAPDURequestCommandAPDUProcessor()

    private val commandAPDUProcessors: List<CommandAPDUProcessor> = listOf(
        ctapCommandFragmentCommandAPDUProcessor,
        ctapCommandFinalFragmentCommandAPDUProcessor,
        ctapContinuationAPDURequestCommandAPDUProcessor,
        u2fRegisterCommandAPDUProcessor,
        u2fAuthenticateCommandAPDUProcessor,
        u2fVersionCommandAPDUProcessor,
        u2fContinuationAPDURequestCommandAPDUProcessor
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

    private interface CommandAPDUProcessor {
        fun isTarget(command: CommandAPDU): Boolean
        suspend fun process(command: CommandAPDU): ResponseAPDU
    }

    inner class SelectCommandAPDUProcessor : CommandAPDUProcessor {
        private val logger = LoggerFactory.getLogger(SelectCommandAPDUProcessor::class.java)
        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x00.toByte() && command.ins == 0xA4.toByte() && command.p1 == 0x04.toByte() && command.p2 == 0x00.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            logger.debug("Processing Select APDU command")
            ctapCommandAPDUQueue.clear()
            ctapResponseQueue.clear()
            u2fResponseQueue.clear()
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
            ctapCommandAPDUQueue.clear()
            ctapResponseQueue.clear()
            u2fResponseQueue.clear()
            val response = ResponseAPDU(null, 0x09.toByte(), 0x00.toByte())
            aidSelected = false
            return response
        }
    }

    inner class CtapCommandFragmentCommandAPDUProcessor : CommandAPDUProcessor {

        private val logger =
            LoggerFactory.getLogger(CtapCommandFragmentCommandAPDUProcessor::class.java)

        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x90.toByte() && command.ins == NFC_CTAP_MSG
            // won't check P1, P2 byte as it may contain flag for NFCCTAP_GETRESPONSE support
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            logger.debug("Processing CTAP2 Non final APDU command")
            ctapCommandAPDUQueue.add(command)
            val sw1 = 0x90.toByte()
            val sw2 = 0x00.toByte()
            return ResponseAPDU(sw1, sw2)
        }

    }

    inner class CtapRequestFinalFragmentCommandAPDUProcessor : CommandAPDUProcessor {

        private val logger =
            LoggerFactory.getLogger(CtapRequestFinalFragmentCommandAPDUProcessor::class.java)

        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x80.toByte() && command.ins == NFC_CTAP_MSG
            // won't check P1, P2 byte as it may contain flag for NFCCTAP_GETRESPONSE support
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            logger.debug("Processing CTAP2 Final APDU command")
            ctapCommandAPDUQueue.add(command)
            val ctapCommand: CtapRequest? = try {
                val cloned: List<CommandAPDU> = ArrayList(ctapCommandAPDUQueue)
                ctapCommandAPDUQueue.clear()
                buildCtapCommand(cloned)
            } catch (e: RuntimeException) {
                logger.error("Failed to build a CTAP2 command from APDU commands", e)
                return ResponseAPDU.createErrorResponseAPDU()
            }
            val ctapResponse = invokeCtapCommand(ctapCommand)
            val bytes = ctapResponseConverter.convertToBytes(ctapResponse)
            ctapResponseQueue.initialize(bytes)
            return ctapResponseQueue.poll(command)
        }

        private suspend fun invokeCtapCommand(ctapRequest: CtapRequest?): CtapResponse {
            return transactionManager.invokeCommand(
                ctapRequest as CtapRequest
            )
        }

        private fun buildCtapCommand(apduCommands: List<CommandAPDU>): CtapRequest {
            val outputStream = ByteArrayOutputStream()
            try {
                for (command in apduCommands) {
                    command.dataIn.let {
                        if (it != null) {
                            outputStream.write(it)
                        }
                    }
                }
            } catch (e: IOException) {
                throw UncheckedIOException(e)
            }
            val bytes = outputStream.toByteArray()
            return ctapRequestConverter.convert(bytes)
        }
    }

    inner class CtapContinuationAPDURequestCommandAPDUProcessor : CommandAPDUProcessor {

        private val logger = LoggerFactory.getLogger(CtapContinuationAPDURequestCommandAPDUProcessor::class.java)

        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x80.toByte() && command.ins == 0xc0.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            return ctapResponseQueue.poll(command)
        }
    }

    inner class U2FRegisterCommandAPDUProcessor : CommandAPDUProcessor {
        private val logger = LoggerFactory.getLogger(U2FRegisterCommandAPDUProcessor::class.java)
        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x00.toByte() &&
                    command.ins == 0x01.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            val dataIn = command.dataIn
            if(dataIn == null){
                logger.debug("command data is missing")
                return ResponseAPDU.createErrorResponseAPDU()
            }
            val u2fRegistrationRequest: U2FRegistrationRequest = U2FRegistrationRequest.createFromCommandAPDU(command)
            try{
                val u2fRegistrationResponse: U2FRegistrationResponse = transactionManager.invokeCommand(u2fRegistrationRequest)
                u2fResponseQueue.initialize(u2fRegistrationResponse.toBytes())
                return u2fResponseQueue.poll(command)
            }
            catch (e: U2FCommandExecutionException){
                logger.error("U2F registration failed", e)
                return ResponseAPDU(e.statusCode.sw1, e.statusCode.sw2)
            }
        }
    }

    inner class U2FAuthenticateCommandAPDUProcessor : CommandAPDUProcessor {

        private val logger =
            LoggerFactory.getLogger(U2FAuthenticateCommandAPDUProcessor::class.java)

        override fun isTarget(command: CommandAPDU): Boolean {
            return command.ins == 0x02.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            val dataIn = command.dataIn
            if(dataIn == null){
                logger.debug("command data is missing")
                return ResponseAPDU.createErrorResponseAPDU()
            }
            val u2fAuthenticationRequest: U2FAuthenticationRequest = U2FAuthenticationRequest.createFromCommandAPDU(command)
            try{
                val u2fAuthenticationResponse: U2FAuthenticationResponse = transactionManager.invokeCommand(u2fAuthenticationRequest)
                u2fResponseQueue.initialize(u2fAuthenticationResponse.toBytes())
                return u2fResponseQueue.poll(command)
            }
            catch (e: U2FCommandExecutionException){
                logger.error("U2F authentication failed", e)
                return ResponseAPDU(e.statusCode.sw1, e.statusCode.sw2)
            }
        }
    }

    inner class U2FVersionCommandAPDUProcessor : CommandAPDUProcessor {
        private val logger = LoggerFactory.getLogger(U2FVersionCommandAPDUProcessor::class.java)
        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x00.toByte() &&
                    command.ins == 0x03.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            val data = "U2F_V2".encodeToByteArray()
            val sw1 = 0x90.toByte()
            val sw2 = 0x00.toByte()
            return ResponseAPDU(data, sw1, sw2)
        }
    }

    inner class U2FContinuationAPDURequestCommandAPDUProcessor : CommandAPDUProcessor {

        private val logger = LoggerFactory.getLogger(CtapContinuationAPDURequestCommandAPDUProcessor::class.java)

        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x00.toByte() && command.ins == 0xc0.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            return u2fResponseQueue.poll(command)
        }
    }

}