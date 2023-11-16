package com.unifidokey.driver.provider

import android.app.Activity
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.webauthn4j.ctap.authenticator.GetAssertionConsentOptions
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentOptions
import com.webauthn4j.ctap.authenticator.UserConsentHandler
import com.webauthn4j.ctap.client.PublicKeyCredentialCreationContext
import com.webauthn4j.ctap.client.CtapClient
import com.webauthn4j.ctap.client.WebAuthnClient
import com.webauthn4j.ctap.client.transport.InProcessTransportAdaptor
import com.webauthn4j.data.AuthenticatorAssertionResponse
import com.webauthn4j.data.PublicKeyCredential
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import org.slf4j.LoggerFactory

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

            when (intent.action) {
                PasskeyCredentialProviderService.CREATE_PASSKEY -> {
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

                        val ctapClient = CtapClient(InProcessTransportAdaptor(ctapAuthenticator))
                        val webAuthnClient = WebAuthnClient(listOf(ctapClient), objectConverter)
                        val publicKeyCredentialCreationOptions = objectConverter.jsonConverter.readValue(callingRequest.requestJson, PublicKeyCredentialCreationOptions::class.java) ?: TODO()

                        val callingAppInfoOrigin = request.callingAppInfo.origin ?: TODO()
                        val origin = Origin(callingAppInfoOrigin)
                        val publicKeyCredentialCreationContext = PublicKeyCredentialCreationContext(origin)
                        val publicKeyCredential = webAuthnClient.create(publicKeyCredentialCreationOptions, publicKeyCredentialCreationContext)
                        val publicKeyCredentialJSON = objectConverter.jsonConverter.writeValueAsString(publicKeyCredential)
                        val result = Intent()
                        val createPublicKeyCredResponse = CreatePublicKeyCredentialResponse(publicKeyCredentialJSON)
                        PendingIntentHandler.setCreateCredentialResponse(result, createPublicKeyCredResponse)
                        activity.setResult(Activity.RESULT_OK, result)
                        activity.finish()
                    }
                }
                PasskeyCredentialProviderService.GET_PASSKEY -> {
                    val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
                    val credentialOptions = request!!.credentialOptions

                    credentialOptions.forEach{
                        when (it) {
                            is GetPublicKeyCredentialOption -> {
                                it.requestData

                                val publicKeyCredentialRequestOptions = objectConverter.jsonConverter.readValue(it.requestJson, PublicKeyCredentialRequestOptions::class.java)!!
                                val publicKeyCredential : PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> = TODO()
                                val publicKeyCredentialJSON = objectConverter.jsonConverter.writeValueAsString(publicKeyCredential)

                                val result = Intent()
                                val passkeyCredential = androidx.credentials.PublicKeyCredential(publicKeyCredentialJSON)
                                PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(passkeyCredential))
                                activity.setResult(AppCompatActivity.RESULT_OK, result)
                                activity.finish()
                            }
                            else -> TODO()
                        }
                    }

                }
                else -> TODO()
            }
        }
        catch (e: RuntimeException){
            logger.error("Failed to process Passkey Intent", e)
            activity.finish()
        }
    }
}