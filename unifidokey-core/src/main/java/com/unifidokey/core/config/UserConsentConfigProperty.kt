package com.unifidokey.core.config

import com.unifidokey.core.setting.UserConsentSetting

class UserConsentConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<UserConsentSetting>(configManager, KEY, UserConsentSetting.IF_REQUIRED) {

    override fun save(value: UserConsentSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): UserConsentSetting {
        return UserConsentSetting.create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "userConsent"
    }
}
