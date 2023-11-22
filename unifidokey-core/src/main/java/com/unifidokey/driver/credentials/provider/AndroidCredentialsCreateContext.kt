package com.unifidokey.driver.credentials.provider

import com.webauthn4j.data.client.Origin

class AndroidCredentialsCreateContext(
    val origin: Origin,
    val packageName: String) {
}