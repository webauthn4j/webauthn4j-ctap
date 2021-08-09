package com.unifidokey.core.adapter

import com.unifidokey.core.setting.KeyStorageSetting
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore

interface UnifidoKeyAuthenticatorPropertyStore : AuthenticatorPropertyStore {
    var keyStorageSetting: KeyStorageSetting
}
