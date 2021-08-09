package com.webauthn4j.ctap.authenticator.store

import java.io.Serializable
import java.time.Instant

/**
 * Core interface for representing user credential of authenticator
 *
 * @param <T> extra data
</T> */
interface UserCredential : Serializable {
    /**
     * @return credentialId
     */
    val credentialId: ByteArray
    val userCredentialKey: UserCredentialKey

    /**
     * Return userHandle
     *
     * @return userHandle
     */
    val userHandle: ByteArray?

    /**
     * Return username
     *
     * @return username
     */
    val username: String

    /**
     * Return displayName
     *
     * @return displayName
     */
    val displayName: String

    /**
     * Return rpId
     *
     * @return rpId
     */
    val rpId: String

    /**
     * Return rpName
     *
     * @return rpName
     */
    val rpName: String

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
     * Return other information used by the authenticator to inform its UI
     *
     * @return other information used by the authenticator to inform its UI
     */
    val otherUI: Serializable?

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