package com.unifidokey.app.handheld.presentation

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.coroutines.future.await
import java.util.concurrent.CompletableFuture

class AuthenticationConsentDialogActivityStarter(private val context: Context) {
    suspend fun startForResult(request: AuthenticationConsentDialogActivityRequest): AuthenticationConsentDialogActivityResponse {
        val onGoingDialogFutureResult =
            CompletableFuture<AuthenticationConsentDialogActivityResponse>()
        registerBroadcastReceiver(onGoingDialogFutureResult)
        val intent = Intent(context, AuthenticationConsentDialogActivity::class.java)
        intent.putExtra(AuthenticationConsentDialogActivity.EXTRA_REQUEST, request)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        context.startActivity(intent)
        return onGoingDialogFutureResult.await()
    }

    private fun registerBroadcastReceiver(onGoingDialogFutureResult: CompletableFuture<AuthenticationConsentDialogActivityResponse>) {
        val localBroadcastManager = LocalBroadcastManager.getInstance(context)
        val filter = IntentFilter()
        filter.addAction(AuthenticationConsentDialogActivity.ACTION_OPEN)
        localBroadcastManager.registerReceiver(
            LocalBroadcastReceiver(onGoingDialogFutureResult),
            filter
        )
    }

    private class LocalBroadcastReceiver(private val onGoingDialogFutureResult: CompletableFuture<AuthenticationConsentDialogActivityResponse>) :
        BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val localBroadcastManager = LocalBroadcastManager.getInstance(context)
            localBroadcastManager.unregisterReceiver(this)
            @Suppress("DEPRECATION")
            val authenticationConsentDialogActivityResponse =
                intent.getSerializableExtra(AuthenticationConsentDialogActivity.EXTRA_RESPONSE) as AuthenticationConsentDialogActivityResponse
            onGoingDialogFutureResult.complete(authenticationConsentDialogActivityResponse)
        }
    }
}