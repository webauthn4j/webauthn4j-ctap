package com.unifidokey.core.adapter

import androidx.lifecycle.LiveData

/**
 * Adaptor for managing CTAP over BLE feature
 */
interface CtapBLEAdapter {

    /**
     * Return BLE adapter is installed or not
     */
    val isBLEAdapterAvailable: Boolean

    /**
     * Return BLE adapter is enabled on the system
     *
     * @return true if available
     */
    val isBLEAdapterEnabled: LiveData<Boolean>

    /**
     * Start pairing
     */
    fun startPairing()

    /**
     * Stop pairing
     */
    fun stopPairing()
}