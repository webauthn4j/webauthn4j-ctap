package com.unifidokey.app.handheld.presentation.helper

import android.content.DialogInterface
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

object BluetoothPairingDialogManager {
    fun show(
        activity: AppCompatActivity?,
        onDismissListener: DialogInterface.OnDismissListener?
    ): AlertDialog {
        return AlertDialog.Builder(activity!!)
            .setTitle("UnifidoKey")
            .setMessage("Bluetooth Pairing is activated. Please connect from your client")
            .setNegativeButton("Cancel") { _: DialogInterface?, _: Int -> }
            .setOnDismissListener(onDismissListener)
            .show()
    }
}