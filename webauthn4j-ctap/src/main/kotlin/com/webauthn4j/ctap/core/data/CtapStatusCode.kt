package com.webauthn4j.ctap.core.data

import com.webauthn4j.util.UnsignedNumberUtil

@Suppress("MemberVisibilityCanBePrivate")
class CtapStatusCode(value: Int) {
    companion object {

        @JvmField
        val CTAP1_ERR_SUCCESS = CtapStatusCode(0x00)
        val CTAP2_OK = CtapStatusCode(0x00)
        val CTAP1_ERR_INVALID_COMMAND = CtapStatusCode(0x01)
        val CTAP1_ERR_INVALID_PARAMETER = CtapStatusCode(0x02)
        val CTAP1_ERR_INVALID_LENGTH = CtapStatusCode(0x03)
        val CTAP1_ERR_INVALID_SEQ = CtapStatusCode(0x04)
        val CTAP1_ERR_TIMEOUT = CtapStatusCode(0x05)
        val CTAP1_ERR_CHANNEL_BUSY = CtapStatusCode(0x06)
        val CTAP1_ERR_LOCK_REQUIRED = CtapStatusCode(0x0A)
        val CTAP1_ERR_INVALID_CHANNEL = CtapStatusCode(0x0B)
        val CTAP2_ERR_CBOR_UNEXPECTED_TYPE = CtapStatusCode(0x11)
        val CTAP2_ERR_INVALID_CBOR = CtapStatusCode(0x12)
        val CTAP2_ERR_MISSING_PARAMETER = CtapStatusCode(0x14)
        val CTAP2_ERR_LIMIT_EXCEEDED = CtapStatusCode(0x15)
        val CTAP2_ERR_UNSUPPORTED_EXTENSION = CtapStatusCode(0x16)
        val CTAP2_ERR_CREDENTIAL_EXCLUDED = CtapStatusCode(0x19)
        val CTAP2_ERR_PROCESSING = CtapStatusCode(0x21)
        val CTAP2_ERR_INVALID_CREDENTIAL = CtapStatusCode(0x22)
        val CTAP2_ERR_USER_ACTION_PENDING = CtapStatusCode(0x23)
        val CTAP2_ERR_OPERATION_PENDING = CtapStatusCode(0x24)
        val CTAP2_ERR_NO_OPERATIONS = CtapStatusCode(0x25)
        val CTAP2_ERR_UNSUPPORTED_ALGORITHM = CtapStatusCode(0x26)
        val CTAP2_ERR_OPERATION_DENIED = CtapStatusCode(0x27)
        val CTAP2_ERR_KEY_STORE_FULL = CtapStatusCode(0x28)
        val CTAP2_ERR_NO_OPERATION_PENDING = CtapStatusCode(0x2A)
        val CTAP2_ERR_UNSUPPORTED_OPTION = CtapStatusCode(0x2B)
        val CTAP2_ERR_INVALID_OPTION = CtapStatusCode(0x2C)
        val CTAP2_ERR_KEEPALIVE_CANCEL = CtapStatusCode(0x2D)
        val CTAP2_ERR_NO_CREDENTIALS = CtapStatusCode(0x2E)
        val CTAP2_ERR_USER_ACTION_TIMEOUT = CtapStatusCode(0x2F)
        val CTAP2_ERR_NOT_ALLOWED = CtapStatusCode(0x30)
        val CTAP2_ERR_PIN_INVALID = CtapStatusCode(0x31)
        val CTAP2_ERR_PIN_BLOCKED = CtapStatusCode(0x32)
        val CTAP2_ERR_PIN_AUTH_INVALID = CtapStatusCode(0x33)
        val CTAP2_ERR_PIN_AUTH_BLOCKED = CtapStatusCode(0x34)
        val CTAP2_ERR_PIN_NOT_SET = CtapStatusCode(0x35)
        val CTAP2_ERR_PIN_REQUIRED = CtapStatusCode(0x36)
        val CTAP2_ERR_PIN_POLICY_VIOLATION = CtapStatusCode(0x37)
        val CTAP2_ERR_PIN_TOKEN_EXPIRED = CtapStatusCode(0x38)
        val CTAP2_ERR_REQUEST_TOO_LARGE = CtapStatusCode(0x39)
        val CTAP2_ERR_ACTION_TIMEOUT = CtapStatusCode(0x3A)
        val CTAP2_ERR_UP_REQUIRED = CtapStatusCode(0x3B)
        val CTAP1_ERR_OTHER = CtapStatusCode(0x7F)

        private val map: Map<CtapStatusCode, String>

        init {
            val tmp: MutableMap<CtapStatusCode, String> = HashMap()
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

        @SuppressWarnings("kotlin:S1479")
        @JvmStatic
        fun create(value: String?): CtapStatusCode {
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
        fun create(value: Byte): CtapStatusCode {
            return CtapStatusCode(UnsignedNumberUtil.getUnsignedByte(value).toInt())
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

        other as CtapStatusCode

        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        return value
    }


}