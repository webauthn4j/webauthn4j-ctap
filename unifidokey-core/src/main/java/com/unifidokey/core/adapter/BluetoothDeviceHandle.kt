package com.unifidokey.core.adapter

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import java.time.Instant

data class BluetoothDeviceHandle(
    val name: String,
    val address: String,
    var lastConnectedAt: Instant?
) {

    private val mutableConnectionState: MutableLiveData<String> = MutableLiveData("disconnected")

    val connectionState: LiveData<String>
        get() = mutableConnectionState

    internal fun setConnectionState(connectionState: String) {
        mutableConnectionState.postValue(connectionState)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BluetoothDeviceHandle) return false

        if (name != other.name) return false
        if (address != other.address) return false
        if (lastConnectedAt != other.lastConnectedAt) return false

        return true
    }

    override fun hashCode(): Int {
        var result = name.hashCode()
        result = 31 * result + address.hashCode()
        result = 31 * result + (lastConnectedAt?.hashCode() ?: 0)
        return result
    }


}
