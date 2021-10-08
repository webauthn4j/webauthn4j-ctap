package com.unifidokey.core.config

import androidx.annotation.Keep
import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant

@Keep
data class BTHIDDeviceHistoryEntry @JsonCreator constructor(
    @JsonProperty("address") val address: String,
    @JsonProperty("lastConnectedAt") var lastConnectedAt: Instant
)