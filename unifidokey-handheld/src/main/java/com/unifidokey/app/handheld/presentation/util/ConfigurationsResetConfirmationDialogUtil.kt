package com.unifidokey.app.handheld.presentation.util

import android.content.Context
import androidx.appcompat.app.AlertDialog
import com.unifidokey.R
import java.util.function.Consumer

object ConfigurationsResetConfirmationDialogUtil {

    fun confirm(context: Context, handler: Consumer<Boolean>) {
        AlertDialog.Builder(context)
            .setTitle(R.string.title_config_reset)
            .setMessage(R.string.summary_config_reset)
            .setPositiveButton(R.string.button_ok){ _, _ -> handler.accept(true)}
            .setNegativeButton(R.string.button_cancel){ _, _ -> handler.accept(false)}
            .show()
    }

}