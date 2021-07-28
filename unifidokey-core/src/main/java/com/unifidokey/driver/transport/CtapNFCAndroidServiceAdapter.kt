package com.unifidokey.driver.transport

import android.app.Application
import android.content.*
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.unifidokey.core.adapter.CtapNFCAdapter
import org.slf4j.LoggerFactory

class CtapNFCAndroidServiceAdapter(private val context: Application) : CtapNFCAdapter,
    AutoCloseable {
    companion object {
        const val FIDO_AID = "A0000006472F0001"
    }

    private val packageManager: PackageManager = context.packageManager
    private val nfcBroadcastReceiver = NFCBroadcastReceiver()
    private val componentName = ComponentName(context, CtapNFCAndroidService::class.java)
    private val nfcAdapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(context)
    private val cardEmulation: CardEmulation? =
        nfcAdapter?.let { CardEmulation.getInstance(nfcAdapter) }

    private val _isNFCAdapterEnabled: Boolean
        get() = isNFCAdapterAvailable && nfcAdapter?.isEnabled ?: false
    private val mutableNFCAdapterEnabled: MutableLiveData<Boolean> =
        MutableLiveData(_isNFCAdapterEnabled)

    override val isNFCAdapterAvailable: Boolean
        get() {
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)) {
                return nfcAdapter != null
            }
            return false
        }

    override val isNFCAdapterEnabled: LiveData<Boolean>
        get() = mutableNFCAdapterEnabled


    init {
        nfcBroadcastReceiver.register(context)
    }

    override fun close() {
        nfcBroadcastReceiver.unregister(context)
    }

    override fun activate() {
        cardEmulation?.registerAidsForService(
            componentName,
            CardEmulation.CATEGORY_OTHER,
            listOf(FIDO_AID)
        )//TODO:revisit
    }

    override fun deactivate() {
        cardEmulation?.removeAidsForService(componentName, CardEmulation.CATEGORY_OTHER)
    }


    val isDefaultServiceForAID: Boolean
        get() {
            val componentName = ComponentName(context, CtapNFCAndroidService::class.java)
            val nfcAdapter = NfcAdapter.getDefaultAdapter(context)
            return if (nfcAdapter == null) {
                throw IllegalStateException("NfcAdaptor is not available.")
            } else {
                val cardEmulation = CardEmulation.getInstance(nfcAdapter)
                cardEmulation.isDefaultServiceForAid(componentName, FIDO_AID)
            }
        }

    private inner class NFCBroadcastReceiver : BroadcastReceiver() {
        private val logger = LoggerFactory.getLogger(NFCBroadcastReceiver::class.java)
        private val adapterStateChangedIntentFilter =
            IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED)

        fun register(context: Context) {
            context.registerReceiver(this, adapterStateChangedIntentFilter)
        }

        fun unregister(context: Context) {
            context.unregisterReceiver(this)
        }

        override fun onReceive(context: Context, intent: Intent) {
            val action = intent.action
            if (action != null) {
                when (action) {
                    NfcAdapter.ACTION_ADAPTER_STATE_CHANGED -> {
                        val nfcAdaptorEnabled = intent.getIntExtra(
                            NfcAdapter.EXTRA_ADAPTER_STATE,
                            -1
                        ) == NfcAdapter.STATE_ON
                        this@CtapNFCAndroidServiceAdapter.mutableNFCAdapterEnabled.setValue(
                            nfcAdaptorEnabled
                        )
                    }
                    else -> throw IllegalStateException()
                }
            }
        }
    }

}