package com.unifidokey.core.config

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

data class BTHIDDeviceHistoryEntry @JsonCreator constructor(
    @JsonProperty("address") val address: String,
    @JsonProperty("lastConnectedAt") var lastConnectedAt: Instant
)