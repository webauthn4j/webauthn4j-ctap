package com.unifidokey.app.handheld.presentation

import android.content.Context
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.DataBindingUtil
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.unifidokey.R
import com.unifidokey.core.adapter.BluetoothDeviceHandle
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.databinding.BluetoothDeviceListItemLayoutBinding

class BluetoothDeviceHandleRecyclerViewAdapter(
    private val context: Context,
    private val bthidService: BTHIDService
) :
    ListAdapter<BluetoothDeviceHandle, BluetoothDeviceHandleRecyclerViewAdapter.ViewHolder>(
        DIFF_CALLBACK
    ) {
    companion object {
        val DIFF_CALLBACK: DiffUtil.ItemCallback<BluetoothDeviceHandle> =
            object : DiffUtil.ItemCallback<BluetoothDeviceHandle>() {
                override fun areItemsTheSame(
                    oldItem: BluetoothDeviceHandle,
                    newItem: BluetoothDeviceHandle
                ): Boolean {
                    return oldItem.address === newItem.address
                }

                override fun areContentsTheSame(
                    oldItem: BluetoothDeviceHandle,
                    newItem: BluetoothDeviceHandle
                ): Boolean {
                    return oldItem == newItem
                }

            }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding: BluetoothDeviceListItemLayoutBinding = DataBindingUtil.inflate(
            LayoutInflater.from(parent.context),
            R.layout.bluetooth_device_list_item_layout,
            parent,
            false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(viewHolder: ViewHolder, position: Int) {
        val bluetoothDeviceHandle = getItem(position)!!
        viewHolder.binding.viewModel = BTHIDDeviceViewModel(bthidService, bluetoothDeviceHandle)
        viewHolder.binding.lifecycleOwner = context as AppCompatActivity
    }

    inner class ViewHolder(val binding: BluetoothDeviceListItemLayoutBinding) :
        RecyclerView.ViewHolder(binding.root)

}