package com.webauthn4j.ctap.authenticator.data.credential

import java.io.Serializable

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
    val userHandle: ByteArray

    /**
     * Return username
     *
     * @return username
     */
    val username: String?

    /**
     * Return displayName
     *
     * @return displayName
     */
    val displayName: String?

    /**
     * Return icon
     *
     * @return icon
     */
    val icon: String?

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
    val rpName: String?

    /**
     * Return rpIcon
     *
     * @return rpIcon
     */
    val rpIcon: String?

    /**
     * Return other information used by the authenticator to inform its UI
     *
     * @return other information used by the authenticator to inform its UI
     */
    val otherUI: Serializable?

}