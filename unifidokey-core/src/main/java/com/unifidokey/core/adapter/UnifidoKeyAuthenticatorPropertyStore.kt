package com.unifidokey.core.adapter

import com.unifidokey.core.setting.KeyStorageSetting
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import java.io.Serializable

interface UnifidoKeyAuthenticatorPropertyStore : AuthenticatorPropertyStore<Serializable?> {
    var keyStorageSetting: KeyStorageSetting
}
