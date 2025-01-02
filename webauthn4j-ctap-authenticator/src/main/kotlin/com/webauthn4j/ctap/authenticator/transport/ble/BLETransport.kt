package com.webauthn4j.ctap.authenticator.transport.ble

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.transport.Transport
import com.webauthn4j.ctap.core.converter.BLEFrameFragmentConverter
import com.webauthn4j.ctap.core.converter.CtapRequestConverter
import com.webauthn4j.ctap.core.converter.CtapResponseConverter
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.ble.BLEContinuationFrameFragment
import com.webauthn4j.ctap.core.data.ble.BLEFrame
import com.webauthn4j.ctap.core.data.ble.BLEFrameCommand
import com.webauthn4j.ctap.core.data.ble.BLEFrameError
import com.webauthn4j.ctap.core.data.ble.BLEFrameFragment
import com.webauthn4j.ctap.core.data.ble.BLEInitializationFrameFragment
import com.webauthn4j.ctap.core.util.internal.ArrayUtil.toHexString
import org.slf4j.LoggerFactory

/**
 * BLE Transport Binding Connector
 */
class BLETransport(val ctapAuthenticator: CtapAuthenticator) : Transport {
    companion object {
        const val MAX_FRAGMENT_SIZE = 256
    }

    private val logger = LoggerFactory.getLogger(BLETransport::class.java)

    private val ctapRequestConverter: CtapRequestConverter = CtapRequestConverter(ctapAuthenticator.objectConverter)
    private val ctapResponseConverter: CtapResponseConverter = CtapResponseConverter(ctapAuthenticator.objectConverter)

    private val bleFrameFragmentParser = BLEFrameFragmentConverter()
    private val bleFrameBuilder = BLEFrameBuilder()

    private var ctapAuthenticatorSession: CtapAuthenticatorSession = ctapAuthenticator.createSession()

    suspend fun onBLEFrameFragmentBytesReceived(bytes: ByteArray, callback: BLEFrameFragmentResponseCallback) {
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
                BLEFrameCommand.PING -> sendResponse(BLEFrame(BLEFrameCommand.PING), callback)
                BLEFrameCommand.MSG -> processMSGBLEFrame(bleFrame, callback)
                BLEFrameCommand.CANCEL -> {
                    ctapAuthenticatorSession = ctapAuthenticator.createSession()
                }
                else -> {
                    logger.error("Unsupported BLE Frame Command is provided.")
                    sendResponse(BLEFrame(BLEFrameError.ERR_INVALID_CMD) ,callback)
                }
            }
        }
    }

    private suspend fun processMSGBLEFrame(bleFrame: BLEFrame, bleFrameFragmentResponseCallback: BLEFrameFragmentResponseCallback) {
        when (val commandData = bleFrame.data) {
            null -> logger.warn("BLE frame data is null")
            else -> {
                val ctapCommand = ctapRequestConverter.convert(commandData)
                val ctapResponse =
                    ctapAuthenticatorSession.invokeCommand<CtapRequest, CtapResponse>(
                        ctapCommand
                    )
                val responseData = ctapResponseConverter.convertToBytes(ctapResponse)
                sendResponse(BLEFrame(BLEFrameCommand.MSG, responseData), bleFrameFragmentResponseCallback)
            }
        }
    }

    private fun sendResponse(response: BLEFrame, bleFrameFragmentResponseCallback: BLEFrameFragmentResponseCallback) {
        logger.debug("Sending CTAP2 Response BLE Frame Fragment")
        val fragments = response.sliceToFragments(MAX_FRAGMENT_SIZE)
        fragments.forEach { fragment ->
            bleFrameFragmentResponseCallback.onBLEFrameFragmentResponse(fragment.bytes)
        }
    }

    fun interface BLEFrameFragmentResponseCallback {
        fun onBLEFrameFragmentResponse(response: ByteArray)
    }

}