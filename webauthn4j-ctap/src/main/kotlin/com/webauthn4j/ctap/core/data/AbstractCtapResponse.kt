package com.webauthn4j.ctap.core.data

abstract class AbstractCtapResponse<T : CtapResponseData> : CtapResponse<T> {
    final override val statusCode: StatusCode
    final override val responseData: T?

    constructor(statusCode: StatusCode, responseData: T?) {
        this.statusCode = statusCode
        this.responseData = responseData
    }

    constructor(statusCode: StatusCode) {
        this.statusCode = statusCode
        responseData = null
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AbstractCtapResponse<*>

        if (statusCode != other.statusCode) return false
        if (responseData != other.responseData) return false

        return true
    }

    override fun hashCode(): Int {
        var result = statusCode.hashCode()
        result = 31 * result + (responseData?.hashCode() ?: 0)
        return result
    }

}
