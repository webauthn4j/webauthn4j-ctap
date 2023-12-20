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
import androidx.fragment.app.FragmentActivity
import com.unifidokey.core.config.ConfigManager
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequestHandler
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequestHandler
import com.webauthn4j.data.client.Origin
import org.slf4j.LoggerFactory

class AndroidCredentialsIntentProcessor(
    private val activity: FragmentActivity,
    configManager: ConfigManager,
    ctapAuthenticator: CtapAuthenticator,
    private val makeCredentialConsentRequestHandler: MakeCredentialConsentRequestHandler,
    private val getAssertionConsentRequestHandler: GetAssertionConsentRequestHandler
) {

    private val logger = LoggerFactory.getLogger(AndroidCredentialsIntentProcessor::class.java)

    private val ctapAuthenticator = ctapAuthenticator.also {
        it.makeCredentialConsentRequestHandler = this.makeCredentialConsentRequestHandler
        it.getAssertionConsentRequestHandler = this.getAssertionConsentRequestHandler
    }
    private val androidCredentialsAuthenticator = AndroidCredentialsAuthenticator(configManager, this.ctapAuthenticator)
    private val objectConverter = this.ctapAuthenticator.objectConverter

    suspend fun processIntent(activity: Activity, intent: Intent){
        try{
            when (intent.action) {
                CredentialProviderAndroidService.CREATE_PASSKEY -> {
                    val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: throw IllegalStateException("Failed to retrieve ProviderCreateCredentialRequest")
                    processProviderCreateCredentialRequest(request)
                }
                CredentialProviderAndroidService.GET_PASSKEY -> {
                    val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: throw IllegalStateException("Failed to retrieve ProviderGetCredentialRequest")
                    processProviderGetCredentialRequest(request)
                }
                else -> throw IllegalStateException("Unexpected intent action supplied.")
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

                    val androidCredentialsGetRequest = objectConverter.jsonConverter.readValue(it.requestJson, AndroidCredentialsGetRequest::class.java) ?: TODO()
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
                else -> throw IllegalStateException("Unexpected CredentialOption is supplied")
            }
        }
    }

}