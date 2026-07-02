package com.webauthn4j.ctap.authenticator.extension

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.UserCredentialBuilder
import com.webauthn4j.ctap.authenticator.execution.CtapCommandExecutionException
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.data.extension.authenticator.*
import com.webauthn4j.util.MACUtil
import java.security.SecureRandom

class HMACSecretExtensionProcessor : RegistrationExtensionProcessor,
    AuthenticationExtensionProcessor {

    companion object {
        private const val DETAILS_ID_HMAC_SECRET_EXTENSION =
            "unifidokey.hmac-secret-extension.secret"
        private val jsonConverter = ObjectConverter().jsonConverter
        private val secureRandom = SecureRandom()
    }

    override val extensionId: String
        get() = HMACSecretRegistrationExtensionAuthenticatorInput.ID

    override fun processRegistrationExtension(
        context: RegistrationExtensionContext,
        userCredentialBuilder: UserCredentialBuilder,
        extensionOutputsBuilder: AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration
    ) {
        if (!supportsRegistrationExtension(context.makeCredentialRequest.extensions)) {
            throw IllegalArgumentException("invalid extension")
        }
        if (context.makeCredentialRequest.extensions?.hmacCreateSecret == true) {
            val credRandomWithUV = ByteArray(32)
            val credRandomWithoutUV = ByteArray(32)
            secureRandom.nextBytes(credRandomWithUV)
            secureRandom.nextBytes(credRandomWithoutUV)
            val userCredentialDetails = jsonConverter.writeValueAsString(
                HMACSecretUserDetails(
                    credRandomWithUV,
                    credRandomWithoutUV
                )
            )
            userCredentialBuilder.details()
                .entry(DETAILS_ID_HMAC_SECRET_EXTENSION, userCredentialDetails)
            extensionOutputsBuilder.setHMACCreateSecret(true)
        }
    }

    override fun supportsRegistrationExtension(extension: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>?): Boolean {
        return extension?.hmacCreateSecret != null
    }

    override fun processAuthenticationExtension(
        context: AuthenticationExtensionContext,
        outputsBuilder: AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication
    ) {
        if (!supportsAuthenticationExtension(context.getAssertionRequest.extensions)) {
            throw IllegalArgumentException("invalid extension")
        }
        //spec| If "up" is set to false, authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION.
        if (context.getAssertionRequest.options?.up == false) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
        }
        val hmacGetSecretAuthenticatorInput =
            context.getAssertionRequest.extensions?.hmacGetSecret!!

        val json = context.credential.details[DETAILS_ID_HMAC_SECRET_EXTENSION]
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
        val hmacSecretUserDetails =
            jsonConverter.readValue(json, HMACSecretUserDetails::class.java)!!
        val platformKeyAgreementKey = hmacGetSecretAuthenticatorInput.keyAgreement
        val saltEnc = hmacGetSecretAuthenticatorInput.saltEnc
        val saltAuth = hmacGetSecretAuthenticatorInput.saltAuth

        //spec| If pinUvAuthProtocol is absent and a pinUvAuthProtocol value of 1 is supported by the authenticator,
        //spec| let the value of pinUvAuthProtocol be 1
        //spec| If pinUvAuthProtocol is absent and a pinUvAuthProtocol value of 1 is not supported by the authenticator,
        //spec| then return CTAP2_ERR_PIN_AUTH_INVALID.
        val pinProtocol = hmacGetSecretAuthenticatorInput.pinUvAuthProtocol
            ?: PinProtocolVersion.VERSION_1
        val protocol = context.ctapAuthenticatorSession.pinUvAuthService.getProtocol(pinProtocol)

        //spec| The authenticator calls decapsulate on the provided platform key-agreement key to obtain a shared secret.
        val sharedSecret = protocol.decapsulate(platformKeyAgreementKey)

        //spec| The authenticator calls verify(shared secret, saltEnc, saltAuth)
        //spec|   If the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID.
        if (!protocol.verify(sharedSecret, saltEnc, saltAuth)) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        //spec| The authenticator obtains salt1 and salt2 by calling decrypt(shared secret, saltEnc).
        //spec| If the decryption fails, or if the result is not 32 or 64 bytes long, return CTAP1_ERR_INVALID_PARAMETER.
        val salt = protocol.decrypt(sharedSecret, saltEnc)

        //spec| The authenticator chooses which CredRandom to use for next step
        //spec| based on whether user verification was done or not in above steps.
        //spec|   If uv bit is set to 1 in the response, let CredRandom be CredRandomWithUV.
        //spec|   If uv bit is set to 0 in the response, let CredRandom be CredRandomWithoutUV.
        val credRandom = when (context.userVerificationPlan) {
            true -> hmacSecretUserDetails.credRandomWithUV
            false -> hmacSecretUserDetails.credRandomWithoutUV
        }

        //spec| The authenticator generates one or two HMAC-SHA-256 values,
        //spec| depending upon whether it received one salt (32 bytes) or two salts (64 bytes):
        //spec|   output1: HMAC-SHA-256(CredRandom, salt1)
        //spec|   output2: HMAC-SHA-256(CredRandom, salt2)
        //spec| The authenticator returns output1 and (when there were two salts) output2, encrypted to the platform using
        //spec| the shared secret, as part of "extensions" parameter:
        //spec|   One salt case: "hmac-secret": encrypt(shared secret, output1)
        //spec|   Two salt case: "hmac-secret": encrypt(shared secret, output1 || output2)
        val hmacGetSecret = when (salt.size) {
            32 -> {
                val output1 = MACUtil.calculateHmacSHA256(salt, credRandom)
                protocol.encrypt(sharedSecret, output1)
            }
            64 -> {
                val salt1 = salt.copyOfRange(0, 32)
                val salt2 = salt.copyOfRange(32, 64)
                val output1 = MACUtil.calculateHmacSHA256(salt1, credRandom)
                val output2 = MACUtil.calculateHmacSHA256(salt2, credRandom)
                protocol.encrypt(sharedSecret, output1.plus(output2))
            }
            else -> throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
        }

        outputsBuilder.setHMACGetSecret(hmacGetSecret)
    }

    override fun supportsAuthenticationExtension(extensions: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>?): Boolean {
        return extensions?.hmacGetSecret != null
    }

    class HMACSecretUserDetails @JsonCreator constructor(
        @JsonProperty("credRandomWithUV") val credRandomWithUV: ByteArray,
        @JsonProperty("credRandomWithoutUV") val credRandomWithoutUV: ByteArray
    ) {

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is HMACSecretUserDetails) return false

            if (!credRandomWithUV.contentEquals(other.credRandomWithUV)) return false
            if (!credRandomWithoutUV.contentEquals(other.credRandomWithoutUV)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = credRandomWithUV.contentHashCode()
            result = 31 * result + credRandomWithoutUV.contentHashCode()
            return result
        }
    }

}