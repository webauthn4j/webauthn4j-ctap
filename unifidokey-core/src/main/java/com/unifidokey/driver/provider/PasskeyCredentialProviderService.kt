package com.unifidokey.driver.provider

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import org.slf4j.LoggerFactory

class PasskeyCredentialProviderService : CredentialProviderService() {

    companion object{
        public val ACCOUNT_NAME = "Android Keystore"
        public val CREATE_PASSKEY = "com.unifidokey.provider.CREATE_PASSKEY"
    }

    private val logger = LoggerFactory.getLogger(PasskeyCredentialProviderService::class.java)

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        try{
            val response: BeginCreateCredentialResponse = processCreateCredentialRequest(request)
            callback.onResult(response)
        }
        catch (e: RuntimeException){
            logger.error("Unexpected error is thrown onBeginCreateCredentialRequest", e)
            callback.onError(CreateCredentialUnknownException())
        }
    }

    private fun processCreateCredentialRequest(request: BeginCreateCredentialRequest): BeginCreateCredentialResponse {
        when (request) {
            is BeginCreatePublicKeyCredentialRequest -> {
                return processCreatePublicKeyCredentialRequest(request)
            }
            else -> throw IllegalStateException("Unexpected ${request.type} is provided.")
        }
    }

    private fun processCreatePublicKeyCredentialRequest(request: BeginCreatePublicKeyCredentialRequest): BeginCreateCredentialResponse {
        // Adding two create entries - one for storing credentials to the 'Personal'
        // account, and one for storing them to the 'Family' account. These
        // accounts are local to this sample app only.
        val createEntries = listOf(
            CreateEntry(ACCOUNT_NAME, createPendingIntent(CREATE_PASSKEY), isAutoSelectAllowed = true)
        )
        return BeginCreateCredentialResponse(createEntries)
    }

    private fun createPendingIntent(action: String): PendingIntent {
        val intent = Intent(action).setPackage(this.packageName)
        val requestCode = (1..9999).random()
        return PendingIntent.getActivity( //TODO: revisit: getBroadcast?
            applicationContext, requestCode,
            intent, (PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        )
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
//        TODO("Not yet implemented")
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        TODO("Not yet implemented")
    }
}