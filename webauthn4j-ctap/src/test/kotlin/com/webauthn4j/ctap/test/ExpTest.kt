package com.webauthn4j.ctap.test

import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import com.webauthn4j.util.MessageDigestUtil
import org.junit.jupiter.api.Test

class ExpTest {

    private val authenticatorDataConverter = AuthenticatorDataConverter(ObjectConverter())

    @Test
    fun test() {
        val hexString =
            "74A6EA9213C99C2F74B22492B320CF40262A94C1A950A0397F29250B60841EF0400000000062B0F4C65A104EBAB094B44529D77BB000200752C3B9BE43AABE77A9CE438A84432FB2A7B01495A5C976028754644361D281A5010203262001215820AE231E098AC25B00A2C06A0C1FB3A7274D099E9822C247AA7DE454ED4125F878225820779617A92179398F31174D9544ED27FD7C2ACF72058E2C95F472D32D55B4086D"
        val data: AuthenticatorData<RegistrationExtensionAuthenticatorOutput> =
            authenticatorDataConverter.convert(HexUtil.decode(hexString))
        data.toString()
    }
}