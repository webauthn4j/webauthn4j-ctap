package com.webauthn4j.ctap.client

import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.util.ArrayUtil
import com.webauthn4j.util.CollectionUtil

@Suppress("CanBePrimaryConstructorProperty")
class GetAssertionsRequest(
    rpId: String,
    clientDataHash: ByteArray,
    allowList: List<PublicKeyCredentialDescriptor>?,
    extensions: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>?,
    userVerification: UserVerificationRequirement?,
    timeout: ULong?,
    clientPINUserVerificationHandler: com.webauthn4j.ctap.client.ClientPINUserVerificationHandler,
    authenticatorUserVerificationHandler: com.webauthn4j.ctap.client.AuthenticatorUserVerificationHandler
) {

    val rpId: String = rpId
    val clientDataHash: ByteArray = ArrayUtil.clone(clientDataHash)
        get() = ArrayUtil.clone(field)
    val allowList: List<PublicKeyCredentialDescriptor>? = CollectionUtil.unmodifiableList(allowList)
    val extensions: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>? =
        extensions
    val userVerification: UserVerificationRequirement? = userVerification
    val timeout: ULong? = timeout
    val clientPINUserVerificationHandler: com.webauthn4j.ctap.client.ClientPINUserVerificationHandler =
        clientPINUserVerificationHandler
    val authenticatorUserVerificationHandler: com.webauthn4j.ctap.client.AuthenticatorUserVerificationHandler =
        authenticatorUserVerificationHandler

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GetAssertionsRequest

        if (rpId != other.rpId) return false
        if (allowList != other.allowList) return false
        if (extensions != other.extensions) return false
        if (userVerification != other.userVerification) return false
        if (timeout != other.timeout) return false
        if (clientPINUserVerificationHandler != other.clientPINUserVerificationHandler) return false
        if (authenticatorUserVerificationHandler != other.authenticatorUserVerificationHandler) return false

        return true
    }

    override fun hashCode(): Int {
        var result = rpId.hashCode()
        result = 31 * result + (allowList?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        result = 31 * result + userVerification.hashCode()
        result = 31 * result + timeout.hashCode()
        result = 31 * result + clientPINUserVerificationHandler.hashCode()
        result = 31 * result + authenticatorUserVerificationHandler.hashCode()
        return result
    }


}
