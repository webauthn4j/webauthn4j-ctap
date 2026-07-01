package com.webauthn4j.ctap.authenticator
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermission
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermissions

import java.time.Duration
import java.time.Instant

/**
 * State associated with a pinUvAuthToken.
 *
 * Each [PinUvAuthProtocol] instance holds one [PinUvAuthTokenState] that tracks
 * the token's permissions, bound RP ID, usage timer, and user-presence / user-verified flags.
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinUvAuthToken-state">6.5.2.1. pinUvAuthToken State</a>
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinUvAuthToken-state-maintenance">6.5.3.2. pinUvAuthToken State Maintenance Functions</a>
 */
class PinUvAuthTokenState(
    private val transportInitialUsageTimeLimit: Duration = DEFAULT_INITIAL_USAGE_TIME_LIMIT,
    private val transportUserPresentTimeLimit: Duration = transportInitialUsageTimeLimit,
    //spec| A max usage time period value, which SHOULD default to a maximum of 10 minutes (600 seconds).
    private val maxUsageTimePeriod: Duration = DEFAULT_MAX_USAGE_TIME_PERIOD
) {

    //spec| A permissions RP ID, initially null.
    var permissionsRpId: String? = null
        internal set

    //spec| A permissions set whose possible values are those of pinUvAuthToken permissions. It is initially empty.
    var permissions: PinUvAuthTokenPermissions = PinUvAuthTokenPermissions()
        internal set

    //spec| A usage timer, initially not running.
    private var usageTimer: Instant? = null

    //spec| An in use flag, initially set to false, meaning that the pinUvAuthToken is not in use.
    //spec| When the in use flag is set to true, the pinUvAuthToken is said to be in use.
    private var inUse: Boolean = false

    //spec| A initial usage time limit, initially not set.
    //spec| beginUsingPinUvAuthToken() sets this value according to the transport the platform is using to communicate with it.
    //spec| The default maximum per-transport initial usage time limit values are:
    //spec|   usb: 30 seconds
    private var initialUsageTimeLimit: Duration = transportInitialUsageTimeLimit

    //spec| A user present time limit defining the length of time the user is considered "present",
    //spec| as represented by the userPresent flag, after user presence is collected.
    //spec| The user present time limit defaults to the same default maximum per-transport values
    //spec| as the initial usage time limit.
    private var userPresentTimeLimit: Duration = transportUserPresentTimeLimit

    //spec| A userVerified flag, initially false.
    private var userVerifiedFlag: Boolean = false

    //spec| A userPresent flag, initially false.
    private var userPresentFlag: Boolean = false

    private var platformHasUsedToken: Boolean = false

    companion object {
        val DEFAULT_INITIAL_USAGE_TIME_LIMIT: Duration = Duration.ofSeconds(30)
        val DEFAULT_MAX_USAGE_TIME_PERIOD: Duration = Duration.ofMinutes(10)
    }

    //spec| beginUsingPinUvAuthToken(userIsPresent)
    //spec|   Set the userPresent flag to the value of userIsPresent.
    //spec|   Set the userVerified flag to true.
    //spec|   Set the initial usage time limit to a transport-specific value, as described in § 6.5.2.1 pinUvAuthToken State.
    //spec|   Start the pinUvAuthToken usage timer, set the in use flag to true,
    //spec|   and assign pinUvAuthTokenUsageTimerObserver() to observe the usage timer. The pinUvAuthToken is now in use.
    internal fun beginUsingPinUvAuthToken(userIsPresent: Boolean) {
        userPresentFlag = userIsPresent
        userVerifiedFlag = true
        initialUsageTimeLimit = transportInitialUsageTimeLimit
        usageTimer = Instant.now()
        inUse = true
        platformHasUsedToken = false
    }

    //spec| pinUvAuthTokenUsageTimerObserver()
    //spec|   This function observes the pinUvAuthToken usage timer and takes appropriate action upon the specified conditions:
    //spec|     If the usage timer is not running, return.
    //spec|     While the overall usage timer has not reached the max usage time period, perform the following substeps:
    //spec|       If the current user present time limit is reached, call clearUserPresentFlag().
    //spec|       If the initial usage time limit is reached without the platform using the pinUvAuthToken
    //spec|       in an authenticator operation then call stopUsingPinUvAuthToken(), and terminate these steps.
    //spec|       If the authenticator does not utilize a rolling timer then continue.
    //spec|       If the authenticator utilizes a rolling timer then:
    //spec|         If the platform uses the pinUvAuthToken in an authenticator operation before the rolling timer expires then:
    //spec|           Set the rolling timer to the applicable initial usage time limit and continue.
    //spec|         Otherwise (implying the rolling timer expires) call stopUsingPinUvAuthToken(), and terminate these steps.
    //spec|     Call stopUsingPinUvAuthToken(), and terminate these steps.
    //
    // The spec models this as a background observer continuously watching the usage timer.
    // This implementation uses lazy evaluation instead: this function is called on-demand
    // when token state is queried (getUserPresentFlagValue, getUserVerifiedFlagValue) or
    // when the token is verified (verifyPinUvAuthParam in PinUvAuthService), rather than
    // running as a background timer. The observable results are equivalent because token
    // state only matters when it is read by an authenticator operation.
    private fun pinUvAuthTokenUsageTimerObserver() {
        val start = usageTimer ?: return
        val elapsed = Duration.between(start, Instant.now())

        if (elapsed >= maxUsageTimePeriod) {
            stopUsingPinUvAuthToken()
            return
        }

        if (elapsed >= userPresentTimeLimit) {
            clearUserPresentFlag()
        }

        if (elapsed >= initialUsageTimeLimit && !platformHasUsedToken) {
            stopUsingPinUvAuthToken()
            return
        }
    }

    internal fun recordPlatformUsage() {
        platformHasUsedToken = true
    }

    //spec| stopUsingPinUvAuthToken()
    //spec|   Set all of the pinUvAuthToken's state variables to their initial values as given in § 6.5.2.1 pinUvAuthToken State.
    internal fun stopUsingPinUvAuthToken() {
        permissionsRpId = null               // initially null
        permissions = PinUvAuthTokenPermissions()             // initially empty
        usageTimer = null                    // initially not running
        inUse = false                        // initially false
        initialUsageTimeLimit = transportInitialUsageTimeLimit  // initially not set
        userPresentTimeLimit = transportUserPresentTimeLimit    // initially same as initial usage time limit
        userVerifiedFlag = false                 // initially false
        userPresentFlag = false                  // initially false
        platformHasUsedToken = false
    }

    // Checks whether the token is currently in use, after running the timer observer.
    internal fun isInUse(): Boolean {
        pinUvAuthTokenUsageTimerObserver()
        return inUse
    }

    //spec| getUserPresentFlagValue() → userPresentFlagValue
    //spec|   If the pinUvAuthToken is in use then set the userPresentFlagValue to the current value of the pinUvAuthToken's userPresent flag.
    //spec|   Otherwise (implying a pinUvAuthToken exists and is not in use, or does not exist), set userPresentFlagValue to false.
    //spec|   Return userPresentFlagValue.
    fun getUserPresentFlagValue(): Boolean {
        pinUvAuthTokenUsageTimerObserver()
        if (inUse) {
            return userPresentFlag
        }
        return false
    }

    //spec| getUserVerifiedFlagValue() → userVerifiedFlagValue
    //spec|   If the pinUvAuthToken is in use then set the userVerifiedFlagValue to the current value of the pinUvAuthToken's userVerified flag.
    //spec|   Otherwise (implying a pinUvAuthToken exists and is not in use, or does not exist), set userVerifiedFlagValue to false.
    //spec|   Return userVerifiedFlagValue.
    fun getUserVerifiedFlagValue(): Boolean {
        pinUvAuthTokenUsageTimerObserver()
        if (inUse) {
            return userVerifiedFlag
        }
        return false
    }

    //spec| clearUserPresentFlag()
    //spec|   If the pinUvAuthToken is in use then set the pinUvAuthToken's userPresent flag to false, otherwise do nothing.
    fun clearUserPresentFlag() {
        if (inUse) {
            userPresentFlag = false
        }
    }

    //spec| clearUserVerifiedFlag()
    //spec|   If the pinUvAuthToken is in use then set the pinUvAuthToken's userVerified flag to false, otherwise do nothing.
    fun clearUserVerifiedFlag() {
        if (inUse) {
            userVerifiedFlag = false
        }
    }

    //spec| clearPinUvAuthTokenPermissionsExceptLbw()
    //spec|   If the pinUvAuthToken is in use then clear all of the pinUvAuthToken's permissions, except for lbw, otherwise do nothing.
    fun clearPinUvAuthTokenPermissionsExceptLbw() {
        if (inUse) {
            permissions = PinUvAuthTokenPermissions(*permissions.filter { it == PinUvAuthTokenPermission.LBW }.toTypedArray())
        }
    }

    internal fun hasPermission(permission: PinUvAuthTokenPermission): Boolean {
        return permission in permissions
    }
}
