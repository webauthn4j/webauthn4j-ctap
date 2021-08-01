package com.unifidokey.app.handheld.presentation

import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.annotation.UiThread
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.unifidokey.R
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication
import com.unifidokey.app.handheld.presentation.util.BluetoothPairingUtil
import com.unifidokey.core.service.BLEService
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.databinding.HomeFragmentBinding
import com.unifidokey.driver.transport.CtapBTHIDAndroidServiceContextualAdapter
import org.slf4j.LoggerFactory


class HomeFragment : Fragment() {
    private val logger = LoggerFactory.getLogger(HomeFragment::class.java)
    private lateinit var unifidoKeyHandHeldApplication: UnifidoKeyHandHeldApplication
    private lateinit var bthidAndroidServiceContextualAdapter: CtapBTHIDAndroidServiceContextualAdapter

    private lateinit var viewModel: HomeViewModel
    private lateinit var bleService: BLEService
    private lateinit var bthidService: BTHIDService

    override fun onAttach(context: Context) {
        super.onAttach(context)
        unifidoKeyHandHeldApplication =
            requireActivity().application as UnifidoKeyHandHeldApplication
        val unifidoKeyComponent = unifidoKeyHandHeldApplication.unifidoKeyComponent
        bthidAndroidServiceContextualAdapter = unifidoKeyComponent.bthidServiceContextualAdapter
        bleService = unifidoKeyComponent.bleService
        bthidService = unifidoKeyComponent.bthidService
    }

    //region## Lifecycle event handlers ##
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this).get(HomeViewModel::class.java)
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        // Setup data binding
        val binding: HomeFragmentBinding =
            DataBindingUtil.inflate(inflater, R.layout.home_fragment, container, false)
        binding.viewModel = viewModel
        binding.lifecycleOwner = this

        initializeBTHIDDeviceRecyclerView(binding)
        initializeRecentHistoryRecyclerView(binding)
        binding.root.findViewById<MaterialButton>(R.id.bthid_pairing_button).setOnClickListener(this::onBTHIDPairingButtonClick)

        return binding.root
    }


    //endregion


    // Methods


    @UiThread
    fun onBTHIDPairingButtonClick(view: View) {
        BluetoothPairingUtil.startPairing(this.requireContext())
    }

    private fun initializeBTHIDDeviceRecyclerView(binding: HomeFragmentBinding) {
        val bthidDeviceRecyclerView =
            binding.root.findViewById<RecyclerView>(R.id.bthid_device_recycler_view)
        val bthidDeviceRecyclerViewAdapter =
            BluetoothDeviceHandleRecyclerViewAdapter(this.requireContext(), bthidService)
        bthidDeviceRecyclerView.adapter = bthidDeviceRecyclerViewAdapter
        bthidDeviceRecyclerViewAdapter.submitList(viewModel.bthidDevices.value)
        viewModel.bthidDevices.observe(
            this.requireActivity(),
            { bthidDevices -> bthidDeviceRecyclerViewAdapter.submitList(bthidDevices) })
    }

    private fun initializeRecentHistoryRecyclerView(binding: HomeFragmentBinding) {
        val recentHistoryRecyclerView =
            binding.root.findViewById<RecyclerView>(R.id.recent_history_recycler_view)
        val recentHistoryRecyclerViewAdapter = HistoryItemRecyclerViewAdapter()
        recentHistoryRecyclerView.adapter = recentHistoryRecyclerViewAdapter
        recentHistoryRecyclerViewAdapter.submitList(viewModel.recentEvents.value)
        viewModel.recentEvents.observe(
            this.requireActivity(),
            { events -> recentHistoryRecyclerViewAdapter.submitList(events) })
    }

}