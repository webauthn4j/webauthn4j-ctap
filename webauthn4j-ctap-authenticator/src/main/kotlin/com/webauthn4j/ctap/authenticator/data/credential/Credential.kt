package com.webauthn4j.ctap.authenticator.data.credential

import java.io.Serializable
import java.time.Instant

interface Credential : Serializable {

    /**
     * @return credentialId
     */
    val credentialId: ByteArray

    val rpIdHash: ByteArray

    val credentialKey: CredentialKey

    /**
     * Return counter
     *
     * @return counter
     */
    val counter: Long

    /**
     * Return createdAt
     *
     * @return createdAt
     */
    val createdAt: Instant


    /**
     * Return extra data
     */
    val details: Map<String, String>

    /**
     * Return `true` if it is resident key. Otherwise return `false`
     *
     * @return `true` if it is resident key. Otherwise `false`
     */
    val isResidentKey: Boolean
}