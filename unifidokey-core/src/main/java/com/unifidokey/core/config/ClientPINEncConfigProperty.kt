package com.unifidokey.core.config

class ClientPINEncConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<ByteArray?>(configManager, KEY, null, ReleaseLevel.PRIVATE, false, false) {

    override fun save(value: ByteArray?) {
        configManager.persistenceAdaptor.saveBytes(KEY, value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): ByteArray? {
        return configManager.persistenceAdaptor.loadBytes(KEY)
    }

    companion object {
        const val KEY = "clientPINEnc"
    }
}
