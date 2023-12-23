package com.unifidokey.core.config

class DeviceWideCounterConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<UInt>(configManager, KEY, 0u, false, false, false) {

    override fun save(value: UInt) {
        configManager.persistenceAdaptor.savePrimitiveInt(KEY, value.toInt())
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): UInt {
        return configManager.persistenceAdaptor.loadPrimitiveInt(KEY).toUInt()
    }


    companion object {
        const val KEY = "deviceWideCounter"
    }
}