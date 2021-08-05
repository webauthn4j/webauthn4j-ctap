package com.unifidokey.core.config

import com.webauthn4j.ctap.authenticator.settings.AttestationStatementFormatSetting
import com.webauthn4j.ctap.authenticator.settings.AttestationStatementFormatSetting.Companion.create

class AttestationStatementFormatConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<AttestationStatementFormatSetting>(
        configManager,
        KEY,
        AttestationStatementFormatSetting.ANDROID_KEY
    ) {

    override fun save(value: AttestationStatementFormatSetting) {
        configManager.persistenceAdaptor.saveString(KEY, value.value)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): AttestationStatementFormatSetting {
        return create(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "attestationStatementFormat"
    }
}