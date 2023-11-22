package com.unifidokey.driver.credentials.provider

import com.webauthn4j.data.client.Origin


data class AndroidCredentialsGetContext(
    val clientDataHash: ByteArray,
    val origin: Origin
)
