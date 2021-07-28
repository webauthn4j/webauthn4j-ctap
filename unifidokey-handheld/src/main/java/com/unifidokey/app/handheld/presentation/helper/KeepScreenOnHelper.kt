package com.unifidokey.app.handheld.presentation.helper

import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import com.unifidokey.app.UnifidoKeyApplication
import com.unifidokey.core.setting.KeepScreenOnSetting

object KeepScreenOnHelper {
    fun configureKeepScreenOnFlag(activity: AppCompatActivity) {
        if (getKeepScreenOnSetting(activity) == KeepScreenOnSetting.ENABLED) {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
    }

    private fun getKeepScreenOnSetting(activity: AppCompatActivity): KeepScreenOnSetting {
        val unifidoKeyApplication = activity.application as UnifidoKeyApplication<*>
        return unifidoKeyApplication.unifidoKeyComponent.configManager.keepScreenOn.value
    }
}