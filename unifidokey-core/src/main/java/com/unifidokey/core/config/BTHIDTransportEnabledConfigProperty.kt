package com.unifidokey.core.config

class BTHIDTransportEnabledConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<Boolean>(configManager, KEY, true) {

    override fun save(value: Boolean) {
        configManager.persistenceAdaptor.savePrimitiveBoolean(KEY, value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): Boolean {
        return configManager.persistenceAdaptor.loadPrimitiveBoolean(KEY)
    }

    companion object {
        const val KEY = "bthidTransportEnabled"
    }
}