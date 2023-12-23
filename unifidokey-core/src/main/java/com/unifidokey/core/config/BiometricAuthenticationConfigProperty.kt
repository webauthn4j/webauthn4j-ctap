package com.unifidokey.core.config

import com.unifidokey.core.setting.BiometricAuthenticationSetting

class BiometricAuthenticationConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<BiometricAuthenticationSetting>(configManager, KEY, BiometricAuthenticationSetting.ENABLED, false, false, true) {

    override fun save(value: BiometricAuthenticationSetting) {
        configManager.persistenceAdaptor.savePrimitiveBoolean(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): BiometricAuthenticationSetting {
        return BiometricAuthenticationSetting.create(configManager.persistenceAdaptor.loadPrimitiveBoolean(KEY))
    }

    companion object {
        const val KEY = "biometricAuthentication"
    }
}
