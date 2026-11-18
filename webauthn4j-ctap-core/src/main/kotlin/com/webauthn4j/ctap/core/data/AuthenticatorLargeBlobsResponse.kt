package com.webauthn4j.ctap.core.data

class AuthenticatorLargeBlobsResponse(status: CtapStatusCode, data: AuthenticatorLargeBlobsResponseData? = null) :
    AbstractCtapResponse<AuthenticatorLargeBlobsResponseData>(status, data)
