package com.webauthn4j.ctap.authenticator.store

import java.io.Serializable
import java.time.Instant

/**
 * Core interface for representing user credential of authenticator
 *
 * @param <T> extra data
</T> */
interface UserCredential : Credential {

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
     * Return other information used by the authenticator to inform its UI
     *
     * @return other information used by the authenticator to inform its UI
     */
    val otherUI: Serializable?

}