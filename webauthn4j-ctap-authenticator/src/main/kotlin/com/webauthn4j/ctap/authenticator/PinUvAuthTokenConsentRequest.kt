package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermissions
import java.io.Serializable

data class PinUvAuthTokenConsentRequest(
    val permissions: PinUvAuthTokenPermissions,
    val rpId: String?,
) : Serializable
