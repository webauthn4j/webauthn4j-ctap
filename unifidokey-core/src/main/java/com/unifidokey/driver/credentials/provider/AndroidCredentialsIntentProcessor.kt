package com.unifidokey.driver.credentials.provider

import android.app.Activity
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import com.unifidokey.core.config.ConfigManager
import com.webauthn4j.ctap.authenticator.Connection
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.GetAssertionConsentOptions
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentOptions
import com.webauthn4j.ctap.authenticator.UserConsentHandler
import com.webauthn4j.data.client.Origin
import org.slf4j.LoggerFactory

class AndroidCredentialsIntentProcessor(
    private val activity: Activity,
    configManager: ConfigManager,
    ctapAuthenticator: CtapAuthenticator
) {

    private val logger = LoggerFactory.getLogger(AndroidCredentialsIntentProcessor::class.java)
    private val androidCredentialsAuthenticator = AndroidCredentialsAuthenticator(configManager, ctapAuthenticator)
    private val objectConverter = ctapAuthenticator.objectConverter

    suspend fun processIntent(activity: Activity, intent: Intent?){
        try{
            if(intent == null){
                TODO()
            }
            when (intent.action) {
                CredentialProviderAndroidService.CREATE_PASSKEY -> {
                    val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: TODO()
                    processProviderCreateCredentialRequest(request)
                }
                CredentialProviderAndroidService.GET_PASSKEY -> {
                    val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: TODO()
                    processProviderGetCredentialRequest(request)
                }
                else -> TODO()
            }
        }
        catch (e: RuntimeException){
            logger.error("Failed to process Passkey Intent", e)
            activity.finish()
        }
    }

    private suspend fun processProviderCreateCredentialRequest(request: ProviderCreateCredentialRequest) {
        val callingRequest = request.callingRequest
        if (callingRequest is CreatePublicKeyCredentialRequest) {

            val credentialCreateRequest = objectConverter.jsonConverter.readValue(callingRequest.requestJson, AndroidCredentialsCreateRequest::class.java) ?: TODO()

            val origin = request.callingAppInfo.origin?.let { Origin(it) } ?: TODO()
            val packageName = request.callingAppInfo.packageName
            val credentialCreateContext = AndroidCredentialsCreateContext(origin, packageName)

            val credentialCreateResponse = androidCredentialsAuthenticator.create(credentialCreateRequest, credentialCreateContext)
            val publicKeyCredentialJSON = objectConverter.jsonConverter.writeValueAsString(credentialCreateResponse)
            val result = Intent()
            val createPublicKeyCredResponse = CreatePublicKeyCredentialResponse(publicKeyCredentialJSON)
            PendingIntentHandler.setCreateCredentialResponse(result, createPublicKeyCredResponse)
            activity.setResult(Activity.RESULT_OK, result)
            activity.finish()
        }
    }

    private suspend fun processProviderGetCredentialRequest(request: ProviderGetCredentialRequest) {
        val credentialOptions = request.credentialOptions
        credentialOptions.forEach{
            when (it) {
                is GetPublicKeyCredentialOption -> {

                    val androidCredentialsGetRequest = objectConverter.jsonConverter.readValue(it.requestJson, AndroidCredentialsGetRequest::class.java)!!
                    val clientDataHash = it.clientDataHash ?: TODO()
                    val origin = request.callingAppInfo.origin?.let { origin -> Origin(origin) } ?: TODO()
                    val androidCredentialsGetContext = AndroidCredentialsGetContext(clientDataHash, origin)
                    val response = androidCredentialsAuthenticator.get(androidCredentialsGetRequest, androidCredentialsGetContext)

                    val publicKeyCredentialJSON = objectConverter.jsonConverter.writeValueAsString(response)

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

}