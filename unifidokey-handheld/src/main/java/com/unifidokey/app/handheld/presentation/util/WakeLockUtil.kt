package com.unifidokey.app.handheld.presentation.util

import android.content.Context
import android.os.PowerManager


object WakeLockUtil {

    fun acquireWakeLock(context: Context){
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        val flags = PowerManager.FULL_WAKE_LOCK or PowerManager.ACQUIRE_CAUSES_WAKEUP + PowerManager.ON_AFTER_RELEASE
        val tag = "com:unifidokey:wakelock"
        val wakelock = powerManager.newWakeLock(flags, WakeLockUtil::class.java.name)
        wakelock.acquire(20000)
    }
}