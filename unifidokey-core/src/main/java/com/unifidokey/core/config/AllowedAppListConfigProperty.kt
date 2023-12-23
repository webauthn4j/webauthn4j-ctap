package com.unifidokey.core.config

import com.unifidokey.core.setting.AllowedAppListSetting

class AllowedAppListConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<AllowedAppListSetting>(configManager, KEY, AllowedAppListSetting.STANDARD, false, false, true) {

    override fun save(value: AllowedAppListSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): AllowedAppListSetting {
        return AllowedAppListSetting.create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "allowedAppList"
    }
}
