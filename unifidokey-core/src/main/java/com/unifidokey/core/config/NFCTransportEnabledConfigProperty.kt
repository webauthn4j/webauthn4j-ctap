package com.unifidokey.core.config

class NFCTransportEnabledConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<Boolean>(configManager, KEY, false, ReleaseLevel.EXPERIMENTAL, false, true) {

    override fun save(value: Boolean) {
        configManager.persistenceAdaptor.savePrimitiveBoolean(KEY, value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): Boolean {
        return configManager.persistenceAdaptor.loadPrimitiveBoolean(KEY)
    }

    companion object {
        const val KEY = "nfcTransportEnabled"
    }
}