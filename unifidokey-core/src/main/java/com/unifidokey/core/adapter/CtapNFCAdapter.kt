package com.unifidokey.core.adapter

import androidx.lifecycle.LiveData

/**
 * Adapter for CTAP over NFC feature
 */
interface CtapNFCAdapter {

    /**
     * Activate NFC feature.
     *
     */
    fun activate()

    /**
     * Deactivate NFC feature
     */
    fun deactivate()

    /**
     * Return NFC adapter is installed or not
     */
    val isNFCAdapterAvailable: Boolean

    /**
     * Return NFC adapter is enabled on the system
     *
     * @return NFC adapter enabled [LiveData]
     */
    val isNFCAdapterEnabled: LiveData<Boolean>
}