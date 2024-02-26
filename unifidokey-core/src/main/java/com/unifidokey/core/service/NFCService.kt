package com.unifidokey.core.service

import androidx.annotation.UiThread
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import com.unifidokey.core.adapter.CtapNFCAdapter
import com.unifidokey.core.config.ConfigManager
import com.webauthn4j.ctap.core.util.internal.BooleanUtil.isTrue

/**
 * Domain service for NFC
 */
class NFCService constructor(
    private val configManager: ConfigManager,
    private val ctapNFCAdapter: CtapNFCAdapter
) {

    private val _nfcStatus = MediatorLiveData<NFCStatus>()

    val isNFCAdapterAvailable: Boolean
        get() = ctapNFCAdapter.isNFCAdapterAvailable
    val isNFCAdapterEnabled: LiveData<Boolean>
        get() = ctapNFCAdapter.isNFCAdapterEnabled
    val isNFCTransportEnabled: LiveData<Boolean>
        get() = configManager.isNFCTransportEnabled.liveData

    val nfcStatus: LiveData<NFCStatus>
        get() = _nfcStatus

    private val currentStatus: NFCStatus
        get() = when {
            !configManager.nfcFeatureFlag -> NFCStatus.NOT_AVAILABLE
            !isNFCAdapterAvailable -> NFCStatus.NOT_AVAILABLE
            isTrue(isNFCTransportEnabled.value) && isTrue(isNFCAdapterEnabled.value) -> NFCStatus.ON
            else -> NFCStatus.OFF
        }

    init {
        _nfcStatus.value = currentStatus
        _nfcStatus.addSource(isNFCTransportEnabled) {
            _nfcStatus.value = currentStatus
        }
        _nfcStatus.addSource(isNFCAdapterEnabled) {
            _nfcStatus.value = currentStatus
        }
        _nfcStatus.observeForever {
            when (it) {
                NFCStatus.ON -> ctapNFCAdapter.activate()
                else -> ctapNFCAdapter.deactivate()
            }
        }
    }

}