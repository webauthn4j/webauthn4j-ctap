package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.settings.ResetProtectionSetting
import com.webauthn4j.ctap.authenticator.settings.ResetProtectionSetting.Companion.create

class ResetProtectionConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<ResetProtectionSetting>(configManager, KEY, ResetProtectionSetting.ENABLED) {

    override fun save(value: ResetProtectionSetting) {
        configManager.persistenceAdaptor.savePrimitiveBoolean(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): ResetProtectionSetting {
        return create(configManager.persistenceAdaptor.loadPrimitiveBoolean(KEY))
    }

    companion object {
        const val KEY = "resetProtection"
    }
}