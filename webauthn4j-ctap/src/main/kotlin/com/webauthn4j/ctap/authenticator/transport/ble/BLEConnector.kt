package com.webauthn4j.ctap.authenticator.transport.ble

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.TransactionManager
import com.webauthn4j.ctap.authenticator.exception.BLEDataProcessingException
import com.webauthn4j.ctap.core.converter.BLEFrameFragmentConverter
import com.webauthn4j.ctap.core.converter.CtapRequestConverter
import com.webauthn4j.ctap.core.converter.CtapResponseConverter
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.ble.*
import com.webauthn4j.ctap.core.util.internal.ArrayUtil.toHexString
import org.slf4j.LoggerFactory

/**
 * BLE Transport Binding Connector
 */
class BLEConnector(
    private val transactionManager: TransactionManager,
    objectConverter: ObjectConverter,
    private val responseBLEFrameFragmentHandler: ResponseBLEFrameFragmentHandler
) {

    companion object {
        const val MAX_FRAGMENT_SIZE = 256
    }

    private val logger = LoggerFactory.getLogger(BLEConnector::class.java)

    private val ctapRequestConverter: CtapRequestConverter = CtapRequestConverter(objectConverter)
    private val ctapResponseConverter: CtapResponseConverter =
        CtapResponseConverter(objectConverter)

    private val bleFrameFragmentParser = BLEFrameFragmentConverter()
    private val bleFrameBuilder = BLEFrameBuilder()

    suspend fun handle(bytes: ByteArray) {
        logger.debug("Processing CTAP2 Request BLE Frame Fragment: {}", toHexString(bytes))
        val frameFragment: BLEFrameFragment = try {
            bleFrameFragmentParser.convert(bytes)
        } catch (e: RuntimeException) {
            throw BLEDataProcessingException("Failed to parse BLE Data frame", e)
        }
        try {
            if (frameFragment is BLEInitializationFrameFragment) {
                bleFrameBuilder.initialize(frameFragment)
            } else {
                if (bleFrameBuilder.isInitialized) {
                    bleFrameBuilder.append(frameFragment as BLEContinuationFrameFragment)
                } else {
                    throw BLEDataProcessingException("Continuation fragment arrived before initialization fragment arrived.")
                }
            }
        } catch (e: RuntimeException) {
            throw BLEDataProcessingException("Failed to build ", e)
        }
        if (bleFrameBuilder.isCompleted) {
            val bleFrame = bleFrameBuilder.build()
            when (bleFrame.cmd) {
                BLEFrameCommand.PING -> sendResponse(BLEFrame(BLEFrameCommand.PING))
                BLEFrameCommand.MSG -> invokeCtapCommand(bleFrame)
                else -> {
                    logger.error("Unsupported BLE Frame Command is provided.")
                    sendResponse(BLEFrame(BLEFrameError.ERR_INVALID_CMD))
                }
            }
        }
    }

    private suspend fun invokeCtapCommand(bleFrame: BLEFrame) {
        when (bleFrame.data) {
            null -> logger.warn("BLE frame data is null")
            else -> {
                val ctapCommand = ctapRequestConverter.convert(bleFrame.data)
                val ctapResponse =
                    transactionManager.invokeCommand<CtapRequest, CtapResponse>(
                        ctapCommand
                    )
                val data = ctapResponseConverter.convertToBytes(ctapResponse)
                sendResponse(BLEFrame(BLEFrameCommand.MSG, data))
            }
        }
    }

    private fun sendResponse(response: BLEFrame) {
        logger.debug("Sending CTAP2 Response BLE Frame Fragment")
        val fragments = response.sliceToFragments(MAX_FRAGMENT_SIZE)
        fragments.forEach { fragment ->
            responseBLEFrameFragmentHandler.onResponse(fragment.bytes)
        }
    }
}