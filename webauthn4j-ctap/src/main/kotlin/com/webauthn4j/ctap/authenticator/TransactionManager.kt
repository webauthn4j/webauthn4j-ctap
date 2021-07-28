package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.*
import kotlinx.coroutines.*

open class TransactionManager(ctapAuthenticator: CtapAuthenticator = CtapAuthenticator()) {

    //single thread worker to synchronize authenticator access
    private val authenticatorWorker = newSingleThreadContext("authenticator-worker")

    private var transaction: Transaction<*, *>? = null

    var ctapAuthenticator: CtapAuthenticator = ctapAuthenticator
        set(value) {
            runBlocking {
                CoroutineScope(authenticatorWorker).launch {
                    field = value
                }.join()
            }
        }

    fun <TC : CtapRequest, TR : CtapResponse<TRD>?, TRD : CtapResponseData> startCommand(command: TC): Transaction<TR, TRD> {
        val deferred: Deferred<TR> = CoroutineScope(authenticatorWorker).async {
            return@async ctapAuthenticator.invokeCommand(command)
        }
        val transaction = Transaction(deferred)
        this.transaction = transaction
        return transaction
    }

    suspend fun <TC : CtapRequest, TR : CtapResponse<TRD>?, TRD : CtapResponseData> invokeCommand(
        command: TC
    ): TR {
        return startCommand<TC, TR, TRD>(command).await()
    }

    fun cancelOnGoingTransaction() {
        transaction?.cancel()
    }

}