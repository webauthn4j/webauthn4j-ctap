package com.webauthn4j.ctap.core.data

import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import java.lang.IllegalArgumentException
import java.nio.ByteBuffer

class U2FRegistrationRequest : AuthenticatorRequest{

    companion object{

        fun createFromCommandAPDU(command: CommandAPDU): U2FRegistrationRequest {
            val dataIn = command.dataIn
            requireNotNull(dataIn) { "command.dataIn must not be null" }
            require(dataIn.size == 64) { "command.dataIn must be 64 bytes length." }
            return U2FRegistrationRequest(dataIn.copyOfRange(0, 32), dataIn.copyOfRange(32, 64))
        }
    }

    val challengeParameter: ByteArray
        get() = ArrayUtil.clone(field)
    val applicationParameter: ByteArray
        get() = ArrayUtil.clone(field)

    constructor(challengeParameter: ByteArray, applicationParameter: ByteArray) {
        this.challengeParameter = ArrayUtil.clone(challengeParameter)
        this.applicationParameter = ArrayUtil.clone(applicationParameter)
    }

    fun toBytes(): ByteArray{
        return ByteBuffer.allocate(64).put(challengeParameter).put(applicationParameter).array()
    }



    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is U2FRegistrationRequest) return false

        if (!challengeParameter.contentEquals(other.challengeParameter)) return false
        if (!applicationParameter.contentEquals(other.applicationParameter)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = challengeParameter.contentHashCode()
        result = 31 * result + applicationParameter.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "U2FRegistrationRequest(challengeParameter=${HexUtil.encodeToString(challengeParameter)}, applicationParameter=${HexUtil.encodeToString(applicationParameter)})"
    }


}