package com.webauthn4j.ctap.authenticator.transport.nfc.apdu

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.execution.U2FCommandExecutionException
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCTransport
import com.webauthn4j.ctap.core.data.U2FAuthenticationRequest
import com.webauthn4j.ctap.core.data.U2FAuthenticationResponse
import com.webauthn4j.ctap.core.data.U2FRegistrationRequest
import com.webauthn4j.ctap.core.data.U2FRegistrationResponse
import com.webauthn4j.ctap.core.data.U2FStatusCode
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import org.slf4j.LoggerFactory

class U2FAPDUProcessor(
) : CommandAPDUProcessor {
    private val logger = LoggerFactory.getLogger(U2FAPDUProcessor::class.java)

    private val u2fResponseQueue = ResponseAPDUQueue()

    private val u2fRegisterCommandAPDUProcessor = U2FRegisterCommandAPDUProcessor()
    private val u2fAuthenticateCommandAPDUProcessor = U2FAuthenticateCommandAPDUProcessor()
    private val u2fVersionCommandAPDUProcessor = U2FVersionCommandAPDUProcessor()
    private val u2fContinuationAPDURequestCommandAPDUProcessor =
        U2FContinuationAPDURequestCommandAPDUProcessor()

    private val commandAPDUProcessors: List<CommandAPDUProcessor> = listOf(
        u2fRegisterCommandAPDUProcessor,
        u2fAuthenticateCommandAPDUProcessor,
        u2fVersionCommandAPDUProcessor,
        u2fContinuationAPDURequestCommandAPDUProcessor
    )

    private var ctapAuthenticatorSession: CtapAuthenticatorSession? = null

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
            logger.error(NFCTransport.UNEXPECTED_EXCEPTION_MESSAGE, e)
            ResponseAPDU.createErrorResponseAPDU()
        }
    }

    fun onConnect(ctapAuthenticatorSession: CtapAuthenticatorSession) {
        this.ctapAuthenticatorSession = ctapAuthenticatorSession
    }

    fun onDisconnect() {
        ctapAuthenticatorSession = null
        u2fResponseQueue.clear()
    }

    inner class U2FRegisterCommandAPDUProcessor : CommandAPDUProcessor {
        private val logger = LoggerFactory.getLogger(U2FRegisterCommandAPDUProcessor::class.java)
        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x00.toByte() &&
                    command.ins == 0x01.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            val dataIn = command.dataIn
            if (dataIn == null) {
                logger.debug("command data is missing")
                return ResponseAPDU.createErrorResponseAPDU()
            }
            val u2fRegistrationRequest: U2FRegistrationRequest = U2FRegistrationRequest.createFromCommandAPDU(command)
            return try {
                ctapAuthenticatorSession.let {
                    if(it == null){
                        throw IllegalStateException("Unexpected U2FRegistrationRequest is passed before connection is established.")
                    }
                    else{
                        val u2fRegistrationResponse: U2FRegistrationResponse = it.invokeCommand(u2fRegistrationRequest)
                        u2fResponseQueue.initialize(u2fRegistrationResponse.toBytes())
                        u2fResponseQueue.poll(command)
                    }
                }
            } catch (e: U2FCommandExecutionException) {
                logger.error("U2F registration failed", e)
                ResponseAPDU(e.statusCode.sw1, e.statusCode.sw2)
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
            if (dataIn == null) {
                logger.debug("command data is missing")
                return ResponseAPDU.createErrorResponseAPDU()
            }
            val u2fAuthenticationRequest: U2FAuthenticationRequest =
                U2FAuthenticationRequest.createFromCommandAPDU(command)
            return try {
                ctapAuthenticatorSession.let {
                    if(it == null){
                        throw IllegalStateException("Unexpected U2FAuthenticationRequest is passed before connection is established.")
                    }
                    else{
                        val u2fAuthenticationResponse: U2FAuthenticationResponse = it.invokeCommand(u2fAuthenticationRequest)
                        u2fResponseQueue.initialize(u2fAuthenticationResponse.toBytes())
                        u2fResponseQueue.poll(command)
                    }
                }
            } catch (e: U2FCommandExecutionException) {
                logger.error("U2F authentication failed", e)
                ResponseAPDU(e.statusCode.sw1, e.statusCode.sw2)
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

        private val logger =
            LoggerFactory.getLogger(U2FContinuationAPDURequestCommandAPDUProcessor::class.java)

        override fun isTarget(command: CommandAPDU): Boolean {
            return command.cla == 0x00.toByte() && command.ins == 0xc0.toByte()
        }

        override suspend fun process(command: CommandAPDU): ResponseAPDU {
            return u2fResponseQueue.poll(command)
        }
    }


}