package com.webauthn4j.ctap.authenticator.extension

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.UserCredentialBuilder
import com.webauthn4j.ctap.authenticator.exception.CtapCommandExecutionException
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.data.extension.authenticator.*
import com.webauthn4j.util.MACUtil
import java.security.SecureRandom
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class HMACSecretExtensionProcessor : RegistrationExtensionProcessor,
    AuthenticationExtensionProcessor {

    companion object{
        private const val DETAILS_ID_HMAC_SECRET_EXTENSION = "unifidokey.hmac-secret-extension.secret"
        private val IV_ZERO = ByteArray(16)
        private val jsonConverter = ObjectConverter().jsonConverter
        private val secureRandom = SecureRandom()
    }

    override val extensionId: String
        get() = HMACSecretRegistrationExtensionAuthenticatorInput.ID

    override fun processRegistrationExtension(
        context: RegistrationExtensionContext,
        userCredentialBuilder: UserCredentialBuilder,
        extensionOutputsBuilder: AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration) {
        if (!supportsRegistrationExtension(context.makeCredentialRequest.extensions)) {
            throw IllegalArgumentException("invalid extension")
        }
        if (context.makeCredentialRequest.extensions?.hmacCreateSecret == true) {
            val credRandomWithUV = ByteArray(32)
            val credRandomWithoutUV = ByteArray(32)
            secureRandom.nextBytes(credRandomWithUV)
            secureRandom.nextBytes(credRandomWithoutUV)
            val userCredentialDetails = jsonConverter.writeValueAsString(HMACSecretUserDetails(credRandomWithUV, credRandomWithoutUV))
            userCredentialBuilder.details().entry(DETAILS_ID_HMAC_SECRET_EXTENSION, userCredentialDetails)
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
        if(context.getAssertionRequest.options?.up == false){
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
        }
        val hmacGetSecretAuthenticatorInput = context.getAssertionRequest.extensions?.hmacGetSecret!!

        val json = context.credential.details[DETAILS_ID_HMAC_SECRET_EXTENSION] ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_OPTION)
        val hmacSecretUserDetails = jsonConverter.readValue(json, HMACSecretUserDetails::class.java)!!
        val platformKeyAgreementKey = hmacGetSecretAuthenticatorInput.keyAgreement
        val saltEnc = hmacGetSecretAuthenticatorInput.saltEnc
        val saltAuth = hmacGetSecretAuthenticatorInput.saltAuth

        //spec| The authenticator waits for user consent.

        //done in MakeCredentialExecution

        //spec| If request asks for user verification, authenticator waits for user verification.
        //spec| - If user verification is requested via Client PIN mechanism, verify the user by verifying the Client PIN parameters in the request as mentioned in the authenticatorGetAssertion steps.
        //spec| - If user verification is requested via built in "uv" method, verify the user by built-in user verification method as mentioned in the authenticatorGetAssertion steps.

        //done in MakeCredentialExecution

        //spec| The authenticator generates "sharedSecret": SHA-256((abG).x) using the private key of authenticatorKeyAgreementKey, "a" and the public key of platformKeyAgreementKey, "bG".
        //spec| - SHA-256 is done over only the "x" curve point of "abG".
        //spec| - See [RFC6090] Section 4.1 and Appendix (C.2) of [SP800-56A] for more ECDH key agreement protocol details and key representation information.
        val sharedSecret = context.ctapAuthenticator.clientPINService.generateSharedSecret(platformKeyAgreementKey)

        //spec| The authenticator verifies saltEnc by generating LEFT(HMAC-SHA-256(sharedSecret, saltEnc), 16) and matching against the input saltAuth parameter.
        val mac = MACUtil.calculateHmacSHA256(saltEnc, sharedSecret, 16)
        if(!mac.contentEquals(saltAuth)){
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_INVALID_OPTION)
        }

        //spec| The authenticator chooses which CredRandom to use for next step based on whether user verification was done or not in above steps.
        //spec| - If uv bit is set to 1 in the response, let CredRandom be CredRandomWithUV.
        //spec| - If uv bit is set to 0 in the response, let CredRandom be CredRandomWithoutUV.
        val credRandom = when(context.userVerificationPlan) {
            true -> hmacSecretUserDetails.credRandomWithUV
            false -> hmacSecretUserDetails.credRandomWithoutUV
        }

        //spec| The authenticator generates one or two HMAC-SHA-256 values, depending upon whether it received one salt (32 bytes) or two salts (64 bytes):
        //spec| - output1: HMAC-SHA-256(CredRandom, salt1)
        //spec| - output2: HMAC-SHA-256(CredRandom, salt2)
        //spec| The authenticator returns output1 and, when there were two salts, output2 encrypted to the platform using sharedSecret as part of "extensions" parameter:
        //spec| - One salt case: "hmac-secret": AES256-CBC(sharedSecret, IV=0, output1 (32 bytes))
        //spec| - Two salt case: "hmac-secret": AES256-CBC(sharedSecret, IV=0, output1 (32 bytes) || output2 (32 bytes))
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val salt = CipherUtil.decryptWithAESCBCNoPadding(saltEnc, secretKey, IV_ZERO)
        val hmacGetSecret: ByteArray
        when (salt.size) {
            32 -> {
                val salt1 = salt
                val output1 = MACUtil.calculateHmacSHA256(salt1, credRandom)
                hmacGetSecret = CipherUtil.encryptWithAESCBCNoPadding(output1, secretKey, IV_ZERO)
            }
            64 -> {
                val salt1 = salt.copyOfRange(0, 32)
                val salt2 = salt.copyOfRange(32, 64)
                val output1 = MACUtil.calculateHmacSHA256(salt1, credRandom)
                val output2 = MACUtil.calculateHmacSHA256(salt2, credRandom)
                val output = output1.plus(output2)
                hmacGetSecret = CipherUtil.encryptWithAESCBCNoPadding(output, secretKey, IV_ZERO)
            }
            else -> TODO("validation should be done at appropriate place")
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