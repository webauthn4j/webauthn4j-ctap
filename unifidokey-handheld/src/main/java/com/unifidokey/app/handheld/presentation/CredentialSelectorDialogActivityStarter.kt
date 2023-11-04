package com.unifidokey.app.handheld.presentation

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.coroutines.future.await
import java.util.concurrent.CompletableFuture

class CredentialSelectorDialogActivityStarter(private val context: Context) {
    suspend fun startForResult(request: CredentialSelectorDialogActivityRequest): CredentialSelectorDialogActivityResponse {
        val onGoingDialogFutureResult =
            CompletableFuture<CredentialSelectorDialogActivityResponse>()
        registerBroadcastReceiver(onGoingDialogFutureResult)
        val intent = Intent(context, CredentialSelectorDialogActivity::class.java)
        intent.putExtra(CredentialSelectorDialogActivity.EXTRA_REQUEST, request)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        context.startActivity(intent)
        return onGoingDialogFutureResult.await()
    }

    private fun registerBroadcastReceiver(onGoingDialogFutureResult: CompletableFuture<CredentialSelectorDialogActivityResponse>) {
        val localBroadcastManager = LocalBroadcastManager.getInstance(context)
        val filter = IntentFilter()
        filter.addAction(CredentialSelectorDialogActivity.ACTION_OPEN)
        localBroadcastManager.registerReceiver(
            LocalBroadcastReceiver(onGoingDialogFutureResult),
            filter
        )
    }

    private class LocalBroadcastReceiver(private val onGoingDialogFutureResult: CompletableFuture<CredentialSelectorDialogActivityResponse>) :
        BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val localBroadcastManager = LocalBroadcastManager.getInstance(context)
            localBroadcastManager.unregisterReceiver(this)
            @Suppress("DEPRECATION")
            val credentialSelectorDialogActivityResponse =
                intent.getSerializableExtra(CredentialSelectorDialogActivity.EXTRA_RESPONSE) as CredentialSelectorDialogActivityResponse
            onGoingDialogFutureResult.complete(credentialSelectorDialogActivityResponse)
        }
    }
}