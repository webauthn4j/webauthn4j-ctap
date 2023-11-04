package com.unifidokey.app.handheld.presentation

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.annotation.UiThread
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.coroutines.future.await
import java.util.concurrent.CompletableFuture

class RegistrationConsentDialogActivityStarter(private val context: Context) {

    @UiThread
    suspend fun startForResult(request: RegistrationConsentDialogActivityRequest): RegistrationConsentDialogActivityResponse {
        val onGoingDialogFutureResult =
            CompletableFuture<RegistrationConsentDialogActivityResponse>()
        registerBroadcastReceiver(onGoingDialogFutureResult)
        val intent = Intent(context, RegistrationConsentDialogActivity::class.java)
        intent.putExtra(RegistrationConsentDialogActivity.EXTRA_REQUEST, request)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        context.startActivity(intent)
        return onGoingDialogFutureResult.await()
    }

    private fun registerBroadcastReceiver(onGoingDialogFutureResult: CompletableFuture<RegistrationConsentDialogActivityResponse>) {
        val localBroadcastManager = LocalBroadcastManager.getInstance(context)
        val filter = IntentFilter()
        filter.addAction(RegistrationConsentDialogActivity.ACTION_OPEN)
        localBroadcastManager.registerReceiver(
            LocalBroadcastReceiver(onGoingDialogFutureResult),
            filter
        )
    }

    private class LocalBroadcastReceiver(private val onGoingDialogFutureResult: CompletableFuture<RegistrationConsentDialogActivityResponse>) :
        BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val localBroadcastManager = LocalBroadcastManager.getInstance(context)
            localBroadcastManager.unregisterReceiver(this)
            @Suppress("DEPRECATION")
            val registrationConsentDialogActivityResponse =
                intent.getSerializableExtra(RegistrationConsentDialogActivity.EXTRA_RESPONSE) as RegistrationConsentDialogActivityResponse
            onGoingDialogFutureResult.complete(registrationConsentDialogActivityResponse)
        }
    }
}