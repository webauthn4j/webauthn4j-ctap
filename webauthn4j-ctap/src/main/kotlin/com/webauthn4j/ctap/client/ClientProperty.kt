package com.webauthn4j.ctap.client

import com.webauthn4j.data.client.Origin

class ClientProperty @JvmOverloads constructor(
    val origin: Origin,
    val clientPIN: String,
    val tokenBindingId: ByteArray? = null
)
