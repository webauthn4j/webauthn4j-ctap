package com.webauthn4j.ctap.authenticator.transport.hybrid

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.execution.CtapCommandExecutionException
import com.webauthn4j.ctap.core.converter.CtapRequestConverter
import com.webauthn4j.ctap.core.converter.CtapResponseConverter
import com.webauthn4j.ctap.core.data.CtapStatusCode
import kotlinx.coroutines.CancellationException
import org.slf4j.LoggerFactory

/** Executes one decrypted Hybrid CTAP message without depending on HID framing. */
class HybridCtapProcessor(private val session: CtapAuthenticatorSession) {
    private val requestConverter = CtapRequestConverter(session.objectConverter)
    private val responseConverter = CtapResponseConverter(session.objectConverter)
    private val logger = LoggerFactory.getLogger(HybridCtapProcessor::class.java)

    suspend fun process(request: ByteArray): ByteArray = try {
        val command = requestConverter.convert(request)
        responseConverter.convertToBytes(session.invokeCommand(command))
    } catch (error: CancellationException) {
        throw error
    } catch (error: CtapCommandExecutionException) {
        byteArrayOf(error.statusCode.byte)
    } catch (error: Exception) {
        logger.error("Unexpected exception while processing Hybrid CTAP command", error)
        byteArrayOf(CtapStatusCode.CTAP1_ERR_OTHER.byte)
    }
}
