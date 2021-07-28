package com.webauthn4j.ctap.core.data

import com.webauthn4j.util.UnsignedNumberUtil

@Suppress("MemberVisibilityCanBePrivate")
class StatusCode(value: Int) {
    companion object {

        @JvmField
        val CTAP1_ERR_SUCCESS = StatusCode(0x00)
        val CTAP2_OK = StatusCode(0x00)
        val CTAP1_ERR_INVALID_COMMAND = StatusCode(0x01)
        val CTAP1_ERR_INVALID_PARAMETER = StatusCode(0x02)
        val CTAP1_ERR_INVALID_LENGTH = StatusCode(0x03)
        val CTAP1_ERR_INVALID_SEQ = StatusCode(0x04)
        val CTAP1_ERR_TIMEOUT = StatusCode(0x05)
        val CTAP1_ERR_CHANNEL_BUSY = StatusCode(0x06)
        val CTAP1_ERR_LOCK_REQUIRED = StatusCode(0x0A)
        val CTAP1_ERR_INVALID_CHANNEL = StatusCode(0x0B)
        val CTAP2_ERR_CBOR_UNEXPECTED_TYPE = StatusCode(0x11)
        val CTAP2_ERR_INVALID_CBOR = StatusCode(0x12)
        val CTAP2_ERR_MISSING_PARAMETER = StatusCode(0x14)
        val CTAP2_ERR_LIMIT_EXCEEDED = StatusCode(0x15)
        val CTAP2_ERR_UNSUPPORTED_EXTENSION = StatusCode(0x16)
        val CTAP2_ERR_CREDENTIAL_EXCLUDED = StatusCode(0x19)
        val CTAP2_ERR_PROCESSING = StatusCode(0x21)
        val CTAP2_ERR_INVALID_CREDENTIAL = StatusCode(0x22)
        val CTAP2_ERR_USER_ACTION_PENDING = StatusCode(0x23)
        val CTAP2_ERR_OPERATION_PENDING = StatusCode(0x24)
        val CTAP2_ERR_NO_OPERATIONS = StatusCode(0x25)
        val CTAP2_ERR_UNSUPPORTED_ALGORITHM = StatusCode(0x26)
        val CTAP2_ERR_OPERATION_DENIED = StatusCode(0x27)
        val CTAP2_ERR_KEY_STORE_FULL = StatusCode(0x28)
        val CTAP2_ERR_NO_OPERATION_PENDING = StatusCode(0x2A)
        val CTAP2_ERR_UNSUPPORTED_OPTION = StatusCode(0x2B)
        val CTAP2_ERR_INVALID_OPTION = StatusCode(0x2C)
        val CTAP2_ERR_KEEPALIVE_CANCEL = StatusCode(0x2D)
        val CTAP2_ERR_NO_CREDENTIALS = StatusCode(0x2E)
        val CTAP2_ERR_USER_ACTION_TIMEOUT = StatusCode(0x2F)
        val CTAP2_ERR_NOT_ALLOWED = StatusCode(0x30)
        val CTAP2_ERR_PIN_INVALID = StatusCode(0x31)
        val CTAP2_ERR_PIN_BLOCKED = StatusCode(0x32)
        val CTAP2_ERR_PIN_AUTH_INVALID = StatusCode(0x33)
        val CTAP2_ERR_PIN_AUTH_BLOCKED = StatusCode(0x34)
        val CTAP2_ERR_PIN_NOT_SET = StatusCode(0x35)
        val CTAP2_ERR_PIN_REQUIRED = StatusCode(0x36)
        val CTAP2_ERR_PIN_POLICY_VIOLATION = StatusCode(0x37)
        val CTAP2_ERR_PIN_TOKEN_EXPIRED = StatusCode(0x38)
        val CTAP2_ERR_REQUEST_TOO_LARGE = StatusCode(0x39)
        val CTAP2_ERR_ACTION_TIMEOUT = StatusCode(0x3A)
        val CTAP2_ERR_UP_REQUIRED = StatusCode(0x3B)
        val CTAP1_ERR_OTHER = StatusCode(0x7F)

        private val map: Map<StatusCode, String>

        init {
            val tmp: MutableMap<StatusCode, String> = HashMap()
            tmp[CTAP2_OK] = "CTAP2_OK"
            tmp[CTAP1_ERR_INVALID_COMMAND] = "CTAP1_ERR_INVALID_COMMAND"
            tmp[CTAP1_ERR_INVALID_PARAMETER] = "CTAP1_ERR_INVALID_PARAMETER"
            tmp[CTAP1_ERR_INVALID_LENGTH] = "CTAP1_ERR_INVALID_LENGTH"
            tmp[CTAP1_ERR_INVALID_SEQ] = "CTAP1_ERR_INVALID_SEQ"
            tmp[CTAP1_ERR_TIMEOUT] = "CTAP1_ERR_TIMEOUT"
            tmp[CTAP1_ERR_CHANNEL_BUSY] = "CTAP1_ERR_CHANNEL_BUSY"
            tmp[CTAP1_ERR_LOCK_REQUIRED] = "CTAP1_ERR_LOCK_REQUIRED"
            tmp[CTAP1_ERR_INVALID_CHANNEL] = "CTAP1_ERR_INVALID_CHANNEL"
            tmp[CTAP2_ERR_CBOR_UNEXPECTED_TYPE] = "CTAP2_ERR_CBOR_UNEXPECTED_TYPE"
            tmp[CTAP2_ERR_INVALID_CBOR] = "CTAP2_ERR_INVALID_CBOR"
            tmp[CTAP2_ERR_MISSING_PARAMETER] = "CTAP2_ERR_MISSING_PARAMETER"
            tmp[CTAP2_ERR_LIMIT_EXCEEDED] = "CTAP2_ERR_LIMIT_EXCEEDED"
            tmp[CTAP2_ERR_UNSUPPORTED_EXTENSION] = "CTAP2_ERR_UNSUPPORTED_EXTENSION"
            tmp[CTAP2_ERR_CREDENTIAL_EXCLUDED] = "CTAP2_ERR_CREDENTIAL_EXCLUDED"
            tmp[CTAP2_ERR_PROCESSING] = "CTAP2_ERR_PROCESSING"
            tmp[CTAP2_ERR_INVALID_CREDENTIAL] = "CTAP2_ERR_INVALID_CREDENTIAL"
            tmp[CTAP2_ERR_USER_ACTION_PENDING] = "CTAP2_ERR_USER_ACTION_PENDING"
            tmp[CTAP2_ERR_OPERATION_PENDING] = "CTAP2_ERR_OPERATION_PENDING"
            tmp[CTAP2_ERR_NO_OPERATIONS] = "CTAP2_ERR_NO_OPERATIONS"
            tmp[CTAP2_ERR_UNSUPPORTED_ALGORITHM] = "CTAP2_ERR_UNSUPPORTED_ALGORITHM"
            tmp[CTAP2_ERR_OPERATION_DENIED] = "CTAP2_ERR_OPERATION_DENIED"
            tmp[CTAP2_ERR_KEY_STORE_FULL] = "CTAP2_ERR_KEY_STORE_FULL"
            tmp[CTAP2_ERR_NO_OPERATION_PENDING] = "CTAP2_ERR_NO_OPERATION_PENDING"
            tmp[CTAP2_ERR_UNSUPPORTED_OPTION] = "CTAP2_ERR_UNSUPPORTED_OPTION"
            tmp[CTAP2_ERR_INVALID_OPTION] = "CTAP2_ERR_INVALID_OPTION"
            tmp[CTAP2_ERR_KEEPALIVE_CANCEL] = "CTAP2_ERR_KEEPALIVE_CANCEL"
            tmp[CTAP2_ERR_NO_CREDENTIALS] = "CTAP2_ERR_NO_CREDENTIALS"
            tmp[CTAP2_ERR_USER_ACTION_TIMEOUT] = "CTAP2_ERR_USER_ACTION_TIMEOUT"
            tmp[CTAP2_ERR_NOT_ALLOWED] = "CTAP2_ERR_NOT_ALLOWED"
            tmp[CTAP2_ERR_PIN_INVALID] = "CTAP2_ERR_PIN_INVALID"
            tmp[CTAP2_ERR_PIN_BLOCKED] = "CTAP2_ERR_PIN_BLOCKED"
            tmp[CTAP2_ERR_PIN_AUTH_INVALID] = "CTAP2_ERR_PIN_AUTH_INVALID"
            tmp[CTAP2_ERR_PIN_AUTH_BLOCKED] = "CTAP2_ERR_PIN_AUTH_BLOCKED"
            tmp[CTAP2_ERR_PIN_NOT_SET] = "CTAP2_ERR_PIN_NOT_SET"
            tmp[CTAP2_ERR_PIN_REQUIRED] = "CTAP2_ERR_PIN_REQUIRED"
            tmp[CTAP2_ERR_PIN_POLICY_VIOLATION] = "CTAP2_ERR_PIN_POLICY_VIOLATION"
            tmp[CTAP2_ERR_PIN_TOKEN_EXPIRED] = "CTAP2_ERR_PIN_TOKEN_EXPIRED"
            tmp[CTAP2_ERR_REQUEST_TOO_LARGE] = "CTAP2_ERR_REQUEST_TOO_LARGE"
            tmp[CTAP2_ERR_ACTION_TIMEOUT] = "CTAP2_ERR_ACTION_TIMEOUT"
            tmp[CTAP2_ERR_UP_REQUIRED] = "CTAP2_ERR_UP_REQUIRED"
            tmp[CTAP1_ERR_OTHER] = "CTAP1_ERR_OTHER"
            map = HashMap(tmp)
        }

        @JvmStatic
        fun create(value: String?): StatusCode {
            return when (value) {
                "CTAP2_OK" -> CTAP2_OK
                "CTAP1_ERR_INVALID_COMMAND" -> CTAP1_ERR_INVALID_COMMAND
                "CTAP1_ERR_INVALID_PARAMETER" -> CTAP1_ERR_INVALID_PARAMETER
                "CTAP1_ERR_INVALID_LENGTH" -> CTAP1_ERR_INVALID_LENGTH
                "CTAP1_ERR_INVALID_SEQ" -> CTAP1_ERR_INVALID_SEQ
                "CTAP1_ERR_TIMEOUT" -> CTAP1_ERR_TIMEOUT
                "CTAP1_ERR_CHANNEL_BUSY" -> CTAP1_ERR_CHANNEL_BUSY
                "CTAP1_ERR_LOCK_REQUIRED" -> CTAP1_ERR_LOCK_REQUIRED
                "CTAP1_ERR_INVALID_CHANNEL" -> CTAP1_ERR_INVALID_CHANNEL
                "CTAP2_ERR_CBOR_UNEXPECTED_TYPE" -> CTAP2_ERR_CBOR_UNEXPECTED_TYPE
                "CTAP2_ERR_INVALID_CBOR" -> CTAP2_ERR_INVALID_CBOR
                "CTAP2_ERR_MISSING_PARAMETER" -> CTAP2_ERR_MISSING_PARAMETER
                "CTAP2_ERR_LIMIT_EXCEEDED" -> CTAP2_ERR_LIMIT_EXCEEDED
                "CTAP2_ERR_UNSUPPORTED_EXTENSION" -> CTAP2_ERR_UNSUPPORTED_EXTENSION
                "CTAP2_ERR_CREDENTIAL_EXCLUDED" -> CTAP2_ERR_CREDENTIAL_EXCLUDED
                "CTAP2_ERR_PROCESSING" -> CTAP2_ERR_PROCESSING
                "CTAP2_ERR_INVALID_CREDENTIAL" -> CTAP2_ERR_INVALID_CREDENTIAL
                "CTAP2_ERR_USER_ACTION_PENDING" -> CTAP2_ERR_USER_ACTION_PENDING
                "CTAP2_ERR_OPERATION_PENDING" -> CTAP2_ERR_OPERATION_PENDING
                "CTAP2_ERR_NO_OPERATIONS" -> CTAP2_ERR_NO_OPERATIONS
                "CTAP2_ERR_UNSUPPORTED_ALGORITHM" -> CTAP2_ERR_UNSUPPORTED_ALGORITHM
                "CTAP2_ERR_OPERATION_DENIED" -> CTAP2_ERR_OPERATION_DENIED
                "CTAP2_ERR_KEY_STORE_FULL" -> CTAP2_ERR_KEY_STORE_FULL
                "CTAP2_ERR_NO_OPERATION_PENDING" -> CTAP2_ERR_NO_OPERATION_PENDING
                "CTAP2_ERR_UNSUPPORTED_OPTION" -> CTAP2_ERR_UNSUPPORTED_OPTION
                "CTAP2_ERR_INVALID_OPTION" -> CTAP2_ERR_INVALID_OPTION
                "CTAP2_ERR_KEEPALIVE_CANCEL" -> CTAP2_ERR_KEEPALIVE_CANCEL
                "CTAP2_ERR_NO_CREDENTIALS" -> CTAP2_ERR_NO_CREDENTIALS
                "CTAP2_ERR_USER_ACTION_TIMEOUT" -> CTAP2_ERR_USER_ACTION_TIMEOUT
                "CTAP2_ERR_NOT_ALLOWED" -> CTAP2_ERR_NOT_ALLOWED
                "CTAP2_ERR_PIN_INVALID" -> CTAP2_ERR_PIN_INVALID
                "CTAP2_ERR_PIN_BLOCKED" -> CTAP2_ERR_PIN_BLOCKED
                "CTAP2_ERR_PIN_AUTH_INVALID" -> CTAP2_ERR_PIN_AUTH_INVALID
                "CTAP2_ERR_PIN_AUTH_BLOCKED" -> CTAP2_ERR_PIN_AUTH_BLOCKED
                "CTAP2_ERR_PIN_NOT_SET" -> CTAP2_ERR_PIN_NOT_SET
                "CTAP2_ERR_PIN_REQUIRED" -> CTAP2_ERR_PIN_REQUIRED
                "CTAP2_ERR_PIN_POLICY_VIOLATION" -> CTAP2_ERR_PIN_POLICY_VIOLATION
                "CTAP2_ERR_PIN_TOKEN_EXPIRED" -> CTAP2_ERR_PIN_TOKEN_EXPIRED
                "CTAP2_ERR_REQUEST_TOO_LARGE" -> CTAP2_ERR_REQUEST_TOO_LARGE
                "CTAP2_ERR_ACTION_TIMEOUT" -> CTAP2_ERR_ACTION_TIMEOUT
                "CTAP2_ERR_UP_REQUIRED" -> CTAP2_ERR_UP_REQUIRED
                "CTAP1_ERR_OTHER" -> CTAP1_ERR_OTHER

                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }

        @JvmStatic
        fun create(value: Byte): StatusCode {
            return StatusCode(UnsignedNumberUtil.getUnsignedByte(value).toInt())
        }

    }

    private val value: Int

    val byte: Byte
        get() = value.toByte()

    init {
        require(!(value > UnsignedNumberUtil.UNSIGNED_BYTE_MAX || value < 0)) { "value must be within unsigned byte" }
        this.value = value
    }


    override fun toString(): String {
        val str = map[this]
        return str ?: String.format("CTAP2_ERR_UNDEFINED(0x%02X)", value)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as StatusCode

        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        return value
    }


}