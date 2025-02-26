package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.core.data.CtapRequest
import com.webauthn4j.ctap.core.data.CtapResponse
import com.webauthn4j.ctap.core.data.CtapStatusCode
import org.slf4j.LoggerFactory

/**
 * Base class for Ctap command execution
 */
abstract class CtapCommandExecutionBase<TC : CtapRequest, TR : CtapResponse>(private val ctapAuthenticatorSession: CtapAuthenticatorSession, private val ctapCommand: TC) {

    private val logger = LoggerFactory.getLogger(CtapCommandExecutionBase::class.java)

    suspend fun execute(): TR {
        logger.info("CTAP Command {}", ctapCommand.toString())

        validate()

        val ctapResponse = try {
            doExecute()
        } catch (e: CtapCommandExecutionException) {
            onFailure(e)
        } catch (e: RuntimeException) {
            logger.error("Unknown error occurred while processing CTAP command.", e)
            onFailure(CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_OTHER, e))
        }
        logger.info("CTAP Response {}", ctapResponse.toString())
        return ctapResponse
    }

    private fun onFailure(e: CtapCommandExecutionException): TR {
        if(e.statusCode == CtapStatusCode.CTAP1_ERR_OTHER){
            logger.error("Failed ctap2 command processing. StatusCode: {} ", e.statusCode, e)
            ctapAuthenticatorSession.reportException(e)
        }
        else{
            logger.debug("Failed ctap2 command processing. StatusCode: {} ", e.statusCode)
        }
        return createErrorResponse(e.statusCode)
    }

    protected abstract val commandName: String
    abstract suspend fun validate()
    protected abstract suspend fun doExecute(): TR
    internal abstract fun createErrorResponse(statusCode: CtapStatusCode): TR
}