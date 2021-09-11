package com.webauthn4j.ctap.authenticator.transport.apdu

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCConnector
import com.webauthn4j.ctap.core.converter.CtapRequestConverter
import com.webauthn4j.ctap.core.converter.CtapResponseConverter
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.UncheckedIOException
import java.util.*

class CTAPAPDUProcessor(
    private val transactionManager: TransactionManager,
    objectConverter: ObjectConverter
) : CommandAPDUProcessor {

    private val logger = LoggerFactory.getLogger(CTAPAPDUProcessor::class.java)

    private val ctapCommandFragmentCommandAPDUProcessor = CtapCommandFragmentCommandAPDUProcessor()
    private val ctapCommandFinalFragmentCommandAPDUProcessor = CtapRequestFinalFragmentCommandAPDUProcessor()
    private val ctapContinuationAPDURequestCommandAPDUProcessor = CtapContinuationAPDURequestCommandAPDUProcessor()

    private val ctapRequestConverter: CtapRequestConverter = CtapRequestConverter(objectConverter)
    private val ctapResponseConverter: CtapResponseConverter = CtapResponseConverter(objectConverter)

    private val commandAPDUProcessors: List<CommandAPDUProcessor> = listOf(
        ctapCommandFragmentCommandAPDUProcessor,
        ctapCommandFinalFragmentCommandAPDUProcessor,
        ctapContinuationAPDURequestCommandAPDUProcessor
    )

    private val ctapCommandAPDUQueue: Queue<CommandAPDU> = LinkedList()
    private val ctapResponseQueue = ResponseAPDUQueue()

    override fun isTarget(command: CommandAPDU): Boolean {
        return commandAPDUProcessors.any { it.isTarget(command) }
    }

    override suspend fun process(command: CommandAPDU): ResponseAPDU {
        return try {
            for (commandAPDUProcessor in commandAPDUProcessors) {
                if (commandAPDUProcessor.isTarget(command)) {
                    return commandAPDUProcessor.process(command)
                }
            }
            logger.debug("Processing Unknown APDU command")
            U2FStatusCode.INS_NOT_SUPPORTED.toResponseAPDU()
        } catch (e: RuntimeException) {
            logger.error(NFCConnector.UNEXPECTED_EXCEPTION_MESSAGE, e)
            ResponseAPDU.createErrorResponseAPDU()
        }
    }

    fun clear() {
        ctapCommandAPDUQueue.clear()
        ctapResponseQueue.clear()
    }

    inner class CtapCommandFragmentCommandAPDUProcessor : CommandAPDUProcessor {

        private val logger =
            LoggerFactory.getLogger(CtapCommandFragmentCommandAPDUProcessor::class.java)

        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x90.toByte() && command.ins == NFCConnector.NFC_CTAP_MSG
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
            return command.cla == 0x80.toByte() && command.ins == NFCConnector.NFC_CTAP_MSG
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
                val ctapResponse = AuthenticatorGenericErrorResponse(CtapStatusCode.CTAP1_ERR_OTHER)
                val bytes = ctapResponseConverter.convertToBytes(ctapResponse)
                ctapResponseQueue.initialize(bytes)
                return ctapResponseQueue.poll(command)
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

}