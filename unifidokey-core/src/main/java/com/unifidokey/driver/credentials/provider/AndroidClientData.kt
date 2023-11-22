package com.unifidokey.driver.credentials.provider

import com.webauthn4j.data.client.ClientDataType
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.Challenge

data class AndroidClientData(
    val type: ClientDataType,
    val challenge: Challenge,
    val origin: Origin,
    val androidPackageName: String
)
