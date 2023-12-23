package com.unifidokey.core.config

import com.unifidokey.core.service.AuthenticatorService
import com.webauthn4j.data.attestation.authenticator.AAGUID

class AAGUIDConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<AAGUID>(configManager, KEY, AuthenticatorService.AAGUID, false, true, true) {

    public override fun save(value: AAGUID) {
        configManager.persistenceAdaptor.saveString(KEY, value.toString())
    }

    @Throws(ConfigNotFoundException::class)
    public override fun load(): AAGUID {
        return AAGUID(configManager.persistenceAdaptor.loadString(KEY))
    }

    companion object {
        const val KEY = "aaguid"
    }
}
