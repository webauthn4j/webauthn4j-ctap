package com.unifidokey.core.config

import com.unifidokey.core.setting.KeyStorageSetting

class KeyStorageConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<KeyStorageSetting>(configManager, KEY, KeyStorageSetting.KEYSTORE, false, true, true) {

    override fun save(value: KeyStorageSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    override fun load(): KeyStorageSetting {
        return KeyStorageSetting.create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "keyStorage"
    }
}