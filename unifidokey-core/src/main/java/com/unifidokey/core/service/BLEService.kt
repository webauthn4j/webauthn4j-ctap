package com.unifidokey.core.service

import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import com.unifidokey.core.adapter.CtapBLEAdapter
import com.unifidokey.core.config.ConfigManager
import com.webauthn4j.ctap.core.util.internal.BooleanUtil.isTrue

/**
 * Domain service for BLE
 */
@Suppress("MemberVisibilityCanBePrivate")
class BLEService constructor(
    private val configManager: ConfigManager,
    private val ctapBLEAdapter: CtapBLEAdapter
) {

    private val _bleStatus = MediatorLiveData<BLEStatus>()

    val isBLEAdapterAvailable: Boolean
        get() = ctapBLEAdapter.isBLEAdapterAvailable
    val isBLETransportEnabled: LiveData<Boolean>
        get() = configManager.isBLETransportEnabled.liveData

    val isBLEAdapterEnabled: LiveData<Boolean>
        get() = ctapBLEAdapter.isBLEAdapterEnabled

    val bleStatus: LiveData<BLEStatus>
        get() = _bleStatus

    private val currentStatus: BLEStatus
        get() = when {
            !configManager.bleFeatureFlag -> BLEStatus.NOT_AVAILABLE
            !isBLEAdapterAvailable -> BLEStatus.NOT_AVAILABLE
            isTrue(isBLETransportEnabled.value) && isTrue(isBLEAdapterEnabled.value) -> BLEStatus.ON
            else -> BLEStatus.OFF
        }

    init {
        _bleStatus.value = currentStatus
        _bleStatus.addSource(isBLETransportEnabled) { source: Boolean? ->
            if (source!! && isBLEAdapterEnabled.value!!) {
                _bleStatus.setValue(BLEStatus.ON)
            } else {
                _bleStatus.setValue(BLEStatus.OFF)
            }
        }
        _bleStatus.addSource(isBLEAdapterEnabled) { source: Boolean ->
            if (source && isBLETransportEnabled.value!!) {
                _bleStatus.setValue(BLEStatus.ON)
            } else {
                _bleStatus.setValue(BLEStatus.OFF)
            }
        }
        _bleStatus.observeForever(this::onBLEStatusChanged)
    }


    fun startPairing() {
        ctapBLEAdapter.startPairing()
    }

    fun stopPairing() {
        ctapBLEAdapter.stopPairing()
    }


    private fun onBLEStatusChanged(bleStatus: BLEStatus) {
//TODO:revisit

//        when (bleStatus) {
//            BLEStatus.ON -> activate()
//            else -> deactivate()
//        }
    }

}