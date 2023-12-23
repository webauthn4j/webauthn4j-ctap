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
import com.unifidokey.core.R
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.setting.AllowedAppListSetting
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.data.client.Origin
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets




class AndroidCredentialsIntentProcessor(
    private val activity: FragmentActivity,
    private val configManager: ConfigManager,
    private val relyingPartyDao: RelyingPartyDao,
    private val ctapAuthenticator: CtapAuthenticator
) {

    private val logger = LoggerFactory.getLogger(AndroidCredentialsIntentProcessor::class.java)
    private val androidCredentialsAuthenticator = AndroidCredentialsAuthenticator(this.ctapAuthenticator, activity, configManager, relyingPartyDao)
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

            val origin = request.callingAppInfo.getOrigin(allowList)?.let { Origin(it) } ?: TODO()
            val packageName = request.callingAppInfo.packageName
            val androidCredentialsCreateContext = AndroidCredentialsCreateContext(origin, packageName)

            val androidCredentialsCreateResponse = androidCredentialsAuthenticator.create(credentialCreateRequest, androidCredentialsCreateContext)
            val publicKeyCredentialJSON = objectConverter.jsonConverter.writeValueAsString(androidCredentialsCreateResponse)
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
                    val origin = request.callingAppInfo.getOrigin(allowList)?.let { origin -> Origin(origin) } ?: TODO()
                    val androidCredentialsGetContext = AndroidCredentialsGetContext(clientDataHash, origin)
                    val androidCredentialsGetResponse = androidCredentialsAuthenticator.get(androidCredentialsGetRequest, androidCredentialsGetContext)

                    val publicKeyCredentialJSON = objectConverter.jsonConverter.writeValueAsString(androidCredentialsGetResponse)

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


    private val allowList: String
        get() {
            val resourceId = when(configManager.allowedAppList.value){
                AllowedAppListSetting.STANDARD -> R.raw.gpm_allow_list
                AllowedAppListSetting.LIMITED -> R.raw.limited_allow_list
            }
            val inputStream = activity.resources.openRawResource(resourceId)
            return String(inputStream.readAllBytes(), StandardCharsets.UTF_8)
        }

}