package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.settings.AttestationTypeSetting

class AttestationTypeConfigProperty  internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<AttestationTypeSetting>(
        configManager,
        KEY,
        AttestationTypeSetting.SELF
    ) {

    override fun save(value: AttestationTypeSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): AttestationTypeSetting {
        return AttestationTypeSetting.create(
            configManager.persistenceAdaptor.loadString(
                KEY
            )
        )
    }

    companion object {
        const val KEY = "attestationType"
    }
}