package com.unifidokey.core.config

import com.unifidokey.core.setting.KeepScreenOnSetting

class KeepScreenOnConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<KeepScreenOnSetting>(configManager, KEY, KeepScreenOnSetting.ENABLED, ReleaseLevel.GA, false, true) {

    override fun save(value: KeepScreenOnSetting) {
        configManager.persistenceAdaptor.savePrimitiveBoolean(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): KeepScreenOnSetting {
        return KeepScreenOnSetting.create(configManager.persistenceAdaptor.loadPrimitiveBoolean(KEY))
    }

    companion object {
        const val KEY = "keepScreenOn"
    }
}
