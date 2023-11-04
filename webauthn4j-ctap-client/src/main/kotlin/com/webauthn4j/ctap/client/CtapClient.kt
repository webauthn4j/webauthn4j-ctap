package com.webauthn4j.ctap.client

import com.webauthn4j.ctap.authenticator.exception.ClientPINUserVerificationCanceledException
import com.webauthn4j.ctap.authenticator.exception.CtapCommandExecutionException
import com.webauthn4j.ctap.client.exception.ResponseDataValidationException
import com.webauthn4j.ctap.client.exception.UPNotSupportedException
import com.webauthn4j.ctap.client.exception.UVNotReadyException
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINRequest
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponse
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionResponse
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.PinProtocolVersion
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.UserPresenceOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.ctap.core.util.internal.KeyAgreementUtil
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.util.ECUtil
import com.webauthn4j.util.MACUtil
import com.webauthn4j.util.MessageDigestUtil
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.Arrays
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Ctap Client, which provides high-level API on the top of [CtapAuthenticatorHandle]
 */
class CtapClient(private val ctapAuthenticatorHandle: CtapAuthenticatorHandle) {

    companion object {
        private const val RESPONSE_DATA_NULL_MESSAGE = "authenticatorClientPIN responseData is null"
        private const val KEY_AGREEMENT_NULL_MESSAGE =
            "authenticatorClientPIN responseData.keyAgreement is null"
        private val ZERO_IV = byteArrayOf(
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00
        )
    }

    suspend fun makeCredential(makeCredentialRequest: MakeCredentialRequest): MakeCredentialResponse {
        val getInfoResponse: AuthenticatorGetInfoResponse = ctapAuthenticatorHandle.getInfo()
        val getInfoResponseData = getInfoResponse.responseData ?: throw ResponseDataValidationException("authenticatorGetInfo responseData is null")
        val userVerificationStrategy = makeUserVerificationStrategy(
            makeCredentialRequest.authenticatorSelection?.userVerification,
            getInfoResponseData.options
        )

        val rk: Boolean = when (getInfoResponseData.options?.rk) {
            ResidentKeyOption.SUPPORTED -> {
                when (makeCredentialRequest.authenticatorSelection?.residentKey) {
                    null -> when (makeCredentialRequest.authenticatorSelection?.isRequireResidentKey) {
                        null -> true
                        true -> true
                        false -> false
                    }
                    ResidentKeyRequirement.REQUIRED -> true
                    ResidentKeyRequirement.PREFERRED -> true
                    ResidentKeyRequirement.DISCOURAGED -> false
                    else -> throw IllegalStateException("Unexpected residentKey option.")
                }
            }
            else -> false
        }

        val authenticatorMakeCredentialResponse = when (userVerificationStrategy) {
            UserVerificationStrategy.AUTHENTICATOR_UV -> {
                makeCredentialRequest.authenticatorUserVerificationHandler.onAuthenticatorUserVerificationStarted()
                val makeCredentialResponse = ctapAuthenticatorHandle.makeCredential(
                    AuthenticatorMakeCredentialRequest(
                        makeCredentialRequest.clientDataHash,
                        makeCredentialRequest.rp,
                        makeCredentialRequest.user,
                        makeCredentialRequest.pubKeyCredParams,
                        makeCredentialRequest.excludeList,
                        makeCredentialRequest.extensions,
                        AuthenticatorMakeCredentialRequest.Options(rk, true),
                        null,
                        null
                    )
                )
                makeCredentialRequest.authenticatorUserVerificationHandler.onAuthenticatorUserVerificationFinished()
                makeCredentialResponse
            }
            UserVerificationStrategy.CLIENT_PIN_UV -> {
                val clientPIN: String
                try {
                    clientPIN =
                        makeCredentialRequest.clientPINUserVerificationHandler.onClientPINRequested()
                } catch (e: ClientPINUserVerificationCanceledException) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_REQUIRED, e)
                }
                val pinToken: ByteArray =
                    requestPINToken(clientPIN.toByteArray(StandardCharsets.UTF_8))
                val pinAuth =
                    MACUtil.calculateHmacSHA256(makeCredentialRequest.clientDataHash, pinToken, 16)
                ctapAuthenticatorHandle.makeCredential(
                    AuthenticatorMakeCredentialRequest(
                        makeCredentialRequest.clientDataHash,
                        makeCredentialRequest.rp,
                        makeCredentialRequest.user,
                        makeCredentialRequest.pubKeyCredParams,
                        makeCredentialRequest.excludeList,
                        makeCredentialRequest.extensions,
                        AuthenticatorMakeCredentialRequest.Options(rk, false),
                        pinAuth,
                        PinProtocolVersion.VERSION_1
                    )
                )
            }
            UserVerificationStrategy.NO_UV -> {
                ctapAuthenticatorHandle.makeCredential(
                    AuthenticatorMakeCredentialRequest(
                        makeCredentialRequest.clientDataHash,
                        makeCredentialRequest.rp,
                        makeCredentialRequest.user,
                        makeCredentialRequest.pubKeyCredParams,
                        makeCredentialRequest.excludeList,
                        makeCredentialRequest.extensions,
                        AuthenticatorMakeCredentialRequest.Options(rk, false),
                        null,
                        null
                    )
                )
            }
        }
        val authenticatorMakeCredentialResponseData = authenticatorMakeCredentialResponse.responseData ?: throw ResponseDataValidationException("authenticatorMakeCredential responseData is null")
        return MakeCredentialResponse(
            authenticatorMakeCredentialResponseData.authenticatorData,
            authenticatorMakeCredentialResponseData.attestationStatement
        )
    }

    suspend fun getAssertions(getAssertionsRequest: GetAssertionsRequest): GetAssertionsResponse {
        val getInfoResponse: AuthenticatorGetInfoResponse = ctapAuthenticatorHandle.getInfo()
        val getInfoResponseData = getInfoResponse.responseData ?: throw ResponseDataValidationException("authenticatorGetInfo responseData is null")
        val userVerificationStrategy = makeUserVerificationStrategy(
            getAssertionsRequest.userVerification,
            getInfoResponseData.options
        )
        val getAssertionResponse = when (userVerificationStrategy) {
            UserVerificationStrategy.AUTHENTICATOR_UV -> {
                getAssertionsRequest.authenticatorUserVerificationHandler.onAuthenticatorUserVerificationStarted()
                val getAssertionResponse: AuthenticatorGetAssertionResponse =
                    ctapAuthenticatorHandle.getAssertion(
                        AuthenticatorGetAssertionRequest(
                            getAssertionsRequest.rpId,
                            getAssertionsRequest.clientDataHash,
                            getAssertionsRequest.allowList,
                            getAssertionsRequest.extensions,
                            AuthenticatorGetAssertionRequest.Options(up = true, uv = true),
                            null,
                            null
                        )
                    )
                getAssertionsRequest.authenticatorUserVerificationHandler.onAuthenticatorUserVerificationFinished()
                getAssertionResponse
            }
            UserVerificationStrategy.CLIENT_PIN_UV -> {
                val clientPIN: String
                try {
                    clientPIN =
                        getAssertionsRequest.clientPINUserVerificationHandler.onClientPINRequested()
                } catch (e: ClientPINUserVerificationCanceledException) {
                    throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_REQUIRED, e)
                }
                val pinToken: ByteArray =
                    requestPINToken(clientPIN.toByteArray(StandardCharsets.UTF_8))
                val pinAuth: ByteArray? =
                    MACUtil.calculateHmacSHA256(getAssertionsRequest.clientDataHash, pinToken, 16)
                ctapAuthenticatorHandle.getAssertion(
                    AuthenticatorGetAssertionRequest(
                        getAssertionsRequest.rpId,
                        getAssertionsRequest.clientDataHash,
                        getAssertionsRequest.allowList,
                        getAssertionsRequest.extensions,
                        AuthenticatorGetAssertionRequest.Options(up = true, uv = false),
                        pinAuth,
                        PinProtocolVersion.VERSION_1
                    )
                )
            }
            UserVerificationStrategy.NO_UV -> {
                ctapAuthenticatorHandle.getAssertion(
                    AuthenticatorGetAssertionRequest(
                        getAssertionsRequest.rpId,
                        getAssertionsRequest.clientDataHash,
                        getAssertionsRequest.allowList,
                        getAssertionsRequest.extensions,
                        AuthenticatorGetAssertionRequest.Options(up = true, uv = false),
                        null,
                        null
                    )
                )
            }
        }
        val getAssertionResponseData = getAssertionResponse.responseData ?: throw ResponseDataValidationException("authenticatorGetAssertion responseData is null")
        val list: MutableList<GetAssertionsResponse.Assertion> = ArrayList()
        list.add(
            GetAssertionsResponse.Assertion(
                getAssertionResponseData.credential,
                getAssertionResponseData.authData,
                getAssertionResponseData.signature,
                getAssertionResponseData.user
            )
        )
        val numberOfCredentials = getAssertionResponseData.numberOfCredentials
        if (numberOfCredentials != null && numberOfCredentials > 1) {
            val numberOfRestCredentials = numberOfCredentials - 1
            requestRestAssertions(list, numberOfRestCredentials)
        }
        return GetAssertionsResponse(list)
    }

    suspend fun setPIN(newPIN: String) {
        val getKeyAgreementSubCommand = AuthenticatorClientPINRequest.createV1GetKeyAgreement()
        val clientPINResponse: AuthenticatorClientPINResponse =
            ctapAuthenticatorHandle.clientPIN(getKeyAgreementSubCommand)
        val platformKeyAgreementKeyPair = ECUtil.createKeyPair()
        val clientPINResponseData = clientPINResponse.responseData ?: throw ResponseDataValidationException(RESPONSE_DATA_NULL_MESSAGE)
        val platformKeyAgreementKey = clientPINResponseData.keyAgreement ?: throw ResponseDataValidationException(KEY_AGREEMENT_NULL_MESSAGE)
        val sharedSecret = MessageDigestUtil.createSHA256().digest(
            KeyAgreementUtil.generateSecret(
                platformKeyAgreementKeyPair.private as ECPrivateKey,
                platformKeyAgreementKey.publicKey as ECPublicKey?
            )
        )
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val newPINBytes = newPIN.toByteArray(StandardCharsets.UTF_8).copyOf(64)
        val newPINEnc = CipherUtil.encryptWithAESCBCNoPadding(newPINBytes, secretKey, ZERO_IV)
        val pinAuth = MACUtil.calculateHmacSHA256(newPINEnc, sharedSecret, 16)
        val setPINSubCommand = AuthenticatorClientPINRequest.createV1SetPIN(
            EC2COSEKey.create((platformKeyAgreementKeyPair.public as ECPublicKey)),
            pinAuth,
            newPINEnc
        )
        ctapAuthenticatorHandle.clientPIN(setPINSubCommand)
    }

    suspend fun changePIN(currentPIN: String, newPIN: String) {
        val getKeyAgreementSubCommand = AuthenticatorClientPINRequest.createV1GetKeyAgreement()
        val clientPINResponse: AuthenticatorClientPINResponse =
            ctapAuthenticatorHandle.clientPIN(getKeyAgreementSubCommand)
        val platformKeyAgreementKeyPair = ECUtil.createKeyPair()
        val clientPINResponseData = clientPINResponse.responseData ?: throw ResponseDataValidationException(RESPONSE_DATA_NULL_MESSAGE)
        val platformKeyAgreementKey = clientPINResponseData.keyAgreement ?: throw ResponseDataValidationException(KEY_AGREEMENT_NULL_MESSAGE)
        val sharedSecret = MessageDigestUtil.createSHA256().digest(
            KeyAgreementUtil.generateSecret(
                platformKeyAgreementKeyPair.private as ECPrivateKey,
                platformKeyAgreementKey.publicKey as ECPublicKey?
            )
        )
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val newPINBytes = newPIN.toByteArray(StandardCharsets.UTF_8).copyOf(64)
        val newPINEnc = CipherUtil.encryptWithAESCBCNoPadding(newPINBytes, secretKey, ZERO_IV)
        val pinHashEnc = CipherUtil.encryptWithAESCBCNoPadding(
            Arrays.copyOf(
                MessageDigestUtil.createSHA256()
                    .digest(currentPIN.toByteArray(StandardCharsets.UTF_8)), 16
            ), secretKey, ZERO_IV
        )
        val newPINEncPinHashEncConcat =
            ByteBuffer.allocate(newPINEnc.size + pinHashEnc.size).put(newPINEnc).put(pinHashEnc)
                .array()
        val pinAuth = MACUtil.calculateHmacSHA256(newPINEncPinHashEncConcat, sharedSecret, 16)
        val setPINSubCommand = AuthenticatorClientPINRequest.createV1ChangePIN(
            EC2COSEKey.create((platformKeyAgreementKeyPair.public as ECPublicKey)),
            pinAuth,
            newPINEnc,
            pinHashEnc
        )
        ctapAuthenticatorHandle.clientPIN(setPINSubCommand)
    }

    suspend fun getRetries(): UInt {
        val getRetriesSubCommand = AuthenticatorClientPINRequest.createV1GetRetries()
        val clientPINResponse = ctapAuthenticatorHandle.clientPIN(getRetriesSubCommand)
        val clientPINResponseData = clientPINResponse.responseData ?: throw ResponseDataValidationException(RESPONSE_DATA_NULL_MESSAGE)
        return clientPINResponseData.retries ?: throw ResponseDataValidationException("authenticatorClientPIN responseData.retries is null")
    }

    suspend fun reset() {
        ctapAuthenticatorHandle.reset()
    }

    private fun makeUserVerificationStrategy(
        userVerificationRequirement: UserVerificationRequirement?,
        authenticatorOptions: AuthenticatorGetInfoResponseData.Options?
    ): UserVerificationStrategy {
        val authenticatorUPOption = authenticatorOptions?.up
        val authenticatorUVOption = authenticatorOptions?.uv
        val authenticatorClientPINOption = authenticatorOptions?.clientPin
        if (authenticatorUPOption !== UserPresenceOption.SUPPORTED) {
            throw UPNotSupportedException("Authenticator doesn't support test of user presence.")
        }
        return when (userVerificationRequirement) {
            UserVerificationRequirement.REQUIRED -> when {
                UserVerificationOption.READY == authenticatorUVOption -> {
                    UserVerificationStrategy.AUTHENTICATOR_UV
                }
                ClientPINOption.SET == authenticatorClientPINOption -> {
                    UserVerificationStrategy.CLIENT_PIN_UV
                }
                else -> throw UVNotReadyException("Authenticator is not ready for clientPIN or authenticator test of user verification.")
            }
            UserVerificationRequirement.PREFERRED, null -> when {
                UserVerificationOption.READY == authenticatorUVOption -> {
                    UserVerificationStrategy.AUTHENTICATOR_UV
                }
                ClientPINOption.SET == authenticatorClientPINOption -> {
                    UserVerificationStrategy.CLIENT_PIN_UV
                }
                else -> UserVerificationStrategy.NO_UV
            }
            UserVerificationRequirement.DISCOURAGED -> UserVerificationStrategy.NO_UV
            else -> throw IllegalStateException()
        }
    }

    private suspend fun requestPINToken(clientPIN: ByteArray): ByteArray {
        val platformKeyAgreementKey = ECUtil.createKeyPair()
        val getKeyAgreementResponse: AuthenticatorClientPINResponse =
            ctapAuthenticatorHandle.clientPIN(AuthenticatorClientPINRequest.createV1GetKeyAgreement())
        val getKeyAgreementResponseData = getKeyAgreementResponse.responseData ?: throw ResponseDataValidationException(RESPONSE_DATA_NULL_MESSAGE)
        val authenticatorKeyAgreementKey = getKeyAgreementResponseData.keyAgreement ?: throw ResponseDataValidationException(KEY_AGREEMENT_NULL_MESSAGE)
        val sharedSecret = MessageDigestUtil.createSHA256().digest(
            KeyAgreementUtil.generateSecret(
                platformKeyAgreementKey.private as ECPrivateKey,
                authenticatorKeyAgreementKey.publicKey as ECPublicKey?
            )
        )
        val secretKey: SecretKey = SecretKeySpec(sharedSecret, "AES")
        val pinHash = Arrays.copyOf(MessageDigestUtil.createSHA256().digest(clientPIN), 16)
        val pinHashEnc = CipherUtil.encryptWithAESCBCNoPadding(pinHash, secretKey, ZERO_IV)
        val getPINTokenResponse: AuthenticatorClientPINResponse = ctapAuthenticatorHandle.clientPIN(
            AuthenticatorClientPINRequest.createV1getPINToken(
                EC2COSEKey.create((platformKeyAgreementKey.public as ECPublicKey)),
                pinHashEnc
            )
        )
        val getPINTokenResponseData = getPINTokenResponse.responseData ?: throw ResponseDataValidationException(RESPONSE_DATA_NULL_MESSAGE)
        if (getPINTokenResponseData.pinToken == null) {
            throw ResponseDataValidationException("authenticatorClientPIN responseData.pinToken is null")
        }
        val pinTokenEnc = getPINTokenResponseData.pinToken
        return CipherUtil.decryptWithAESCBCNoPadding(
            pinTokenEnc,
            secretKey,
            ZERO_IV
        ) //decrypt pinTokenEnc to pinToken
    }

    private suspend fun requestRestAssertions(
        list: MutableList<GetAssertionsResponse.Assertion>,
        counter: Int
    ) {
        return if (counter == 0) {
            return
        } else {
            val getNextAssertionResponse: AuthenticatorGetNextAssertionResponse =
                ctapAuthenticatorHandle.getNextAssertion()
            val getNextAssertionResponseData = getNextAssertionResponse.responseData ?: throw ResponseDataValidationException("authenticatorGetNextAssertion responseData is null")
            val assertion = GetAssertionsResponse.Assertion(
                getNextAssertionResponseData.credential,
                getNextAssertionResponseData.authData,
                getNextAssertionResponseData.signature,
                getNextAssertionResponseData.user
            )
            list.add(assertion)
            requestRestAssertions(list, counter - 1)
        }
    }

}