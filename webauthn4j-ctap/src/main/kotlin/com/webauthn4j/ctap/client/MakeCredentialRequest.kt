package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.data.*
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class MakeCredentialRequest(
    clientDataHash: ByteArray,
    rp: CtapPublicKeyCredentialRpEntity,
    user: CtapPublicKeyCredentialUserEntity,
    pubKeyCredParams: List<PublicKeyCredentialParameters>,
    excludeList: List<PublicKeyCredentialDescriptor>?,
    extensions: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>?,
    authenticatorSelection: AuthenticatorSelectionCriteria?,
    timeout: Long?,
    clientPINUserVerificationHandler: ClientPINUserVerificationHandler,
    authenticatorUserVerificationHandler: AuthenticatorUserVerificationHandler
) {

    val clientDataHash: ByteArray = ArrayUtil.clone(clientDataHash)
        get() = ArrayUtil.clone(field)
    val rp: CtapPublicKeyCredentialRpEntity = rp
    val user: CtapPublicKeyCredentialUserEntity = user
    val pubKeyCredParams: List<PublicKeyCredentialParameters> = pubKeyCredParams.toList()
    val excludeList: List<PublicKeyCredentialDescriptor>? = excludeList?.toList()
    val extensions: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>? =
        extensions
    val authenticatorSelection: AuthenticatorSelectionCriteria? = authenticatorSelection
    val timeout: Long? = timeout
    val clientPINUserVerificationHandler: ClientPINUserVerificationHandler =
        clientPINUserVerificationHandler
    val authenticatorUserVerificationHandler: AuthenticatorUserVerificationHandler =
        authenticatorUserVerificationHandler

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as MakeCredentialRequest

        if (rp != other.rp) return false
        if (user != other.user) return false
        if (pubKeyCredParams != other.pubKeyCredParams) return false
        if (excludeList != other.excludeList) return false
        if (extensions != other.extensions) return false
        if (authenticatorSelection != other.authenticatorSelection) return false
        if (timeout != other.timeout) return false
        if (clientPINUserVerificationHandler != other.clientPINUserVerificationHandler) return false
        if (authenticatorUserVerificationHandler != other.authenticatorUserVerificationHandler) return false

        return true
    }

    override fun hashCode(): Int {
        var result = rp.hashCode()
        result = 31 * result + user.hashCode()
        result = 31 * result + pubKeyCredParams.hashCode()
        result = 31 * result + (excludeList?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        result = 31 * result + authenticatorSelection.hashCode()
        result = 31 * result + timeout.hashCode()
        result = 31 * result + clientPINUserVerificationHandler.hashCode()
        result = 31 * result + authenticatorUserVerificationHandler.hashCode()
        return result
    }


}