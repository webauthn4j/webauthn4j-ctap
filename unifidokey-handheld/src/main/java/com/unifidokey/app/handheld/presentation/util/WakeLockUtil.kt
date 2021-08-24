package com.unifidokey.app.handheld.presentation.util

import android.content.Context
import android.os.PowerManager
import android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON


object WakeLockUtil {

    fun acquireWakeLock(context: Context){
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        val flags = FLAG_KEEP_SCREEN_ON  or PowerManager.ACQUIRE_CAUSES_WAKEUP + PowerManager.ON_AFTER_RELEASE
        val wakelock = powerManager.newWakeLock(flags, WakeLockUtil::class.java.name)
        wakelock.acquire(20000)
    }
}