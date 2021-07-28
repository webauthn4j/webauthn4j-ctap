package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.settings.UserVerificationSetting.Companion.create

class UserVerificationConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<UserVerificationSetting>(
        configManager,
        KEY,
        UserVerificationSetting.NOT_SUPPORTED
    ) {

    override fun save(value: UserVerificationSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): UserVerificationSetting {
        return create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "userVerification"
    }
}
