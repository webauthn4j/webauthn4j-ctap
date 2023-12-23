package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.data.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.data.settings.CredentialSelectorSetting.Companion.create

class CredentialSelectorConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<CredentialSelectorSetting>(
        configManager,
        KEY,
        CredentialSelectorSetting.CLIENT_PLATFORM,
        true,
        false,
        true
    ) {

    override fun save(value: CredentialSelectorSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): CredentialSelectorSetting {
        return create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "credentialSelector"
    }
}