package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.authenticator.exception.CtapCommandExecutionException
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.StatusCode
import org.slf4j.LoggerFactory

abstract class CtapCommandExecutionBase<TC : CtapRequest, TR : CtapResponse<*>>(private val ctapAuthenticator: CtapAuthenticator, private val ctapCommand: TC) {

    private val logger = LoggerFactory.getLogger(CtapCommandExecutionBase::class.java)

    suspend fun execute(): TR {
        logger.info("CTAP Command {}", ctapCommand.toString())
        val ctapResponse = try {
            doExecute()
        } catch (e: CtapCommandExecutionException) {
            onFailure(e)
        } catch (e: RuntimeException) {
            logger.error("Unknown error occurred while processing CTAP command.", e)
            onFailure(CtapCommandExecutionException(StatusCode.CTAP1_ERR_OTHER, e))
        }
        logger.info("CTAP Response {}", ctapResponse.toString())
        return ctapResponse
    }

    private fun onFailure(e: CtapCommandExecutionException): TR {
        if(e.statusCode == StatusCode.CTAP1_ERR_OTHER){
            logger.error("Failed ctap2 command processing. StatusCode: {} ", e.statusCode, e)
            ctapAuthenticator.reportException(e)
        }
        else{
            logger.debug("Failed ctap2 command processing. StatusCode: {} ", e.statusCode)
        }
        return createErrorResponse(e.statusCode)
    }

    protected abstract val commandName: String
    protected abstract suspend fun doExecute(): TR
    internal abstract fun createErrorResponse(statusCode: StatusCode): TR
}