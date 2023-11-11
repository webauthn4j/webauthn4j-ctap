package com.unifidokey.driver.provider

import android.app.Activity
import android.content.Intent
import android.util.Log
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.webauthn.AuthenticatorAttestationResponse
import androidx.credentials.webauthn.AuthenticatorResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.ctap.authenticator.GetAssertionConsentOptions
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentOptions
import com.webauthn4j.ctap.authenticator.UserConsentHandler
import com.webauthn4j.ctap.client.ClientProperty
import com.webauthn4j.ctap.client.CtapAuthenticatorHandle
import com.webauthn4j.ctap.client.WebAuthnClient
import com.webauthn4j.ctap.client.transport.InProcessTransportAdaptor
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.client.Origin
import com.webauthn4j.util.Base64UrlUtil
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.json.JSONObject
import org.slf4j.LoggerFactory
import java.security.KeyPair
import java.security.PublicKey

object PasskeyIntentProcessor {

    private val logger = LoggerFactory.getLogger(PasskeyIntentProcessor::class.java)

    suspend fun processIntent(activity: Activity, intent: Intent?){
        try{
            val unifidoKeyApplication = activity.applicationContext as UnifidoKeyApplicationBase<*>
            val configManager = unifidoKeyApplication.unifidoKeyComponent.configManager
            val objectConverter = unifidoKeyApplication.unifidoKeyComponent.objectConverter

            if(intent == null){
                TODO()
            }

            if(intent.action == PasskeyCredentialProviderService.CREATE_PASSKEY) {
                val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
                if(request==null){
                    TODO()
                }
                val callingRequest = request.callingRequest
                if (callingRequest is CreatePublicKeyCredentialRequest) {
                    //TODO: show biometric dialog

                    val ctapAuthenticator = unifidoKeyApplication.unifidoKeyComponent.authenticatorService.ctapAuthenticator
                    ctapAuthenticator.userConsentHandler = object : UserConsentHandler {
                        override suspend fun consentMakeCredential(options: MakeCredentialConsentOptions): Boolean {
                            return true
                        }

                        override suspend fun consentGetAssertion(options: GetAssertionConsentOptions): Boolean {
                            return true
                        }

                    }

                    val ctapAuthenticatorHandle = CtapAuthenticatorHandle(InProcessTransportAdaptor(ctapAuthenticator))
                    val webAuthnClient = WebAuthnClient(listOf(ctapAuthenticatorHandle))
                    val publicKeyCredentialCreationOptions = objectConverter.jsonConverter.readValue(callingRequest.requestJson, PublicKeyCredentialCreationOptions::class.java) ?: TODO()


                    val callingAppInfoOrigin = request.callingAppInfo.origin ?: TODO()
                    val callingAppInfoPackageName = request.callingAppInfo.packageName
                    val clientDataHash = (request.callingRequest as CreatePublicKeyCredentialRequest).clientDataHash
                    val origin = Origin(callingAppInfoOrigin)
                    val clientPIN = "" //TODO: Providing ClientPIN through clientProperty is really appropriate ClientProperty design?
                    val clientProperty = ClientProperty(origin, clientPIN)

                    val publicKeyCredential = webAuthnClient.create(publicKeyCredentialCreationOptions, clientProperty)
                    val attestationObject = objectConverter.cborConverter.readValue(publicKeyCredential.authenticatorResponse?.attestationObject, AttestationObject::class.java)




                    val request = androidx.credentials.webauthn.PublicKeyCredentialCreationOptions(callingRequest.requestJson)


                    val credentialPublicKey = objectConverter.cborConverter.writeValueAsBytes(attestationObject!!.authenticatorData.attestedCredentialData!!.coseKey)

                    val response = AuthenticatorAttestationResponse(
                        requestOptions = request,
                        credentialId = publicKeyCredential.rawId,
                        credentialPublicKey = credentialPublicKey, //CBOR
                        origin = callingAppInfoOrigin,
                        up = attestationObject.authenticatorData.isFlagUP,
                        uv = attestationObject.authenticatorData.isFlagUV,
                        be = false,
                        bs = false,
                        packageName = callingAppInfoPackageName,
                        clientDataHash = clientDataHash
                    )

                    //TODO easy accessor fields

                    val credential = FidoPublicKeyCredential(
                        rawId = publicKeyCredential.rawId, response = response , authenticatorAttachment = "platform"
                    )

                    //add easy accessors fields as defined in https://github.com/w3c/webauthn/pull/1887
                    val authenticatorData = Base64UrlUtil.encodeToString(AuthenticatorDataConverter(objectConverter).convert(attestationObject.authenticatorData))
                    val credentialJson = populateEasyAccessorFields(
                        credential.json(),
                        attestationObject.authenticatorData.attestedCredentialData!!.coseKey.publicKey!!,
                        authenticatorData
                    )

                    val result = Intent()
                    val createPublicKeyCredResponse = CreatePublicKeyCredentialResponse(credentialJson)
                    PendingIntentHandler.setCreateCredentialResponse(result, createPublicKeyCredResponse)
                    activity.setResult(Activity.RESULT_OK, result)
                    activity.finish()
                }
            }
        }
        catch (e: RuntimeException){
            logger.error("Failed to process Passkey Intent", e)
            activity.finish()
        }
    }

    fun fidoJson(rawId: ByteArray, authenticatorAttachment: String, response: AuthenticatorResponse): String {
        // See RegistrationResponseJSON at
        // https://w3c.github.io/webauthn/#ref-for-dom-publickeycredential-tojson
        val encodedId = Base64UrlUtil.encode(rawId)
        val ret = JSONObject()
        ret.put("id", encodedId)
        ret.put("rawId", encodedId)
        ret.put("type", "public-key")
        ret.put("authenticatorAttachment", authenticatorAttachment)
        ret.put("response", response.json())
        ret.put("clientExtensionResults", JSONObject())

        return ret.toString()
    }

//    fun responseJson(): JSONObject {
//        // See AuthenticatorAttestationResponseJSON at
//        // https://w3c.github.io/webauthn/#ref-for-dom-publickeycredential-tojson
//
//        val response = JSONObject()
//        response.put("attestationObject", Base64UrlUtil.encode(attestationObject))
//        response.put("transports", JSONArray(listOf("internal", "hybrid")))
//
//        return response
//    }

    private fun populateEasyAccessorFields(
        json: String,
        publicKey: PublicKey,
        authenticatorData: String
    ):String{
        Log.d("MyCredMan","=== populateEasyAccessorFields BEFORE === "+ json)
        val response = Json.decodeFromString<CreatePublicKeyCredentialResponseJson>(json)
        response.response.publicKeyAlgorithm = -7 // ES256
        response.response.publicKey = Base64UrlUtil.encodeToString(publicKey.encoded)
        response.response.authenticatorData = authenticatorData

        Log.d("MyCredMan","=== populateEasyAccessorFields AFTER === "+ Json.encodeToString(response))
        return Json.encodeToString(response)

    }

    @Serializable
    private data class CreatePublicKeyCredentialResponseJson(
        //RegistrationResponseJSON
        val id:String,
        val rawId: String,
        val response: Response,
        val authenticatorAttachment: String?,
        val clientExtensionResults: EmptyClass = EmptyClass(),
        val type: String,
    ) {
        @Serializable
        data class Response(
            //AuthenticatorAttestationResponseJSON
            val clientDataJSON: String? = null,
            var authenticatorData: String? = null,
            val transports: List<String>? = arrayOf("internal").toList(),
            var publicKey: String? = null, // easy accessors fields
            var publicKeyAlgorithm: Long? =null, // easy accessors fields
            val attestationObject: String? // easy accessors fields
        )
        @Serializable
        class EmptyClass
    }

}