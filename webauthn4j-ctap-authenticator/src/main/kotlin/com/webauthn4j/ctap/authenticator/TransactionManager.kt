package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.AuthenticatorRequest
import com.webauthn4j.ctap.core.data.AuthenticatorResponse
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.runBlocking

/**
 * Ctap Command transaction manager
 */
open class TransactionManager(ctapAuthenticator: CtapAuthenticator = CtapAuthenticator()) {

    //single thread worker to synchronize authenticator access
    private val authenticatorWorker = newSingleThreadContext("authenticator-worker")

    private var transaction: Transaction<*>? = null

    var ctapAuthenticator: CtapAuthenticator = ctapAuthenticator
        set(value) {
            runBlocking {
                CoroutineScope(authenticatorWorker).launch {
                    field = value
                }.join()
            }
        }

    fun <TC : AuthenticatorRequest, TR : AuthenticatorResponse> startCommand(command: TC): Transaction<TR> {
        val deferred: Deferred<TR> = CoroutineScope(authenticatorWorker).async {
            return@async ctapAuthenticator.invokeCommand(command)
        }
        val transaction = Transaction(deferred)
        this.transaction = transaction
        return transaction
    }

    suspend fun <TC : AuthenticatorRequest, TR : AuthenticatorResponse> invokeCommand(
        command: TC
    ): TR {
        return startCommand<TC, TR>(command).await()
    }

    fun cancelOnGoingTransaction() {
        transaction?.cancel()
    }

    fun lock(timeMillis: Long) {
        runBlocking {
            CoroutineScope(authenticatorWorker).launch {
                delay(timeMillis)
            }.join()
        }
    }

}