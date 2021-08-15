package com.unifidokey.app.handheld.presentation

import java.io.Serializable
import java.time.Instant

class CredentialViewModel(
    val id: ByteArray,
    val username: String?,
    val displayName: String?,
    val rpId: String?,
    val rpName: String?,
    val counter: Long,
    val createdAt: Instant
) : Serializable