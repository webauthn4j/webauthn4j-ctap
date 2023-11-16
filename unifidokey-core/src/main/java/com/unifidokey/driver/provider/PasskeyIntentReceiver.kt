package com.unifidokey.driver.provider

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.driver.provider.PasskeyCredentialProviderService.Companion.CREATE_PASSKEY
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.client.PublicKeyCredentialCreationContext
import com.webauthn4j.ctap.client.PublicKeyCredentialRequestContext
import com.webauthn4j.ctap.client.WebAuthnClient
import com.webauthn4j.ctap.client.transport.InProcessTransportAdaptor
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.client.Origin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory

class PasskeyIntentReceiver : BroadcastReceiver() {

    private val logger = LoggerFactory.getLogger(PasskeyIntentReceiver::class.java)

    override fun onReceive(context: Context, intent: Intent?) {
        val unifidoKeyApplication = context.applicationContext as UnifidoKeyApplicationBase<*>
        val configManager = unifidoKeyApplication.unifidoKeyComponent.configManager
        val objectConverter = unifidoKeyApplication.unifidoKeyComponent.objectConverter
        if(intent == null){
            TODO()
        }

        if(intent.action == CREATE_PASSKEY) {
            val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            if(request==null){
                TODO()
            }
            val callingRequest = request.callingRequest
            if (callingRequest is CreatePublicKeyCredentialRequest) {
                val ctapAuthenticator = CtapAuthenticator() //TODO
                ctapAuthenticator.credentialSelectionHandler

                val ctapClient = com.webauthn4j.ctap.client.CtapClient(InProcessTransportAdaptor(ctapAuthenticator))
                val webAuthnClient = WebAuthnClient(listOf(ctapClient), objectConverter)
                val publicKeyCredentialCreationOptions = objectConverter.jsonConverter.readValue(callingRequest.requestJson, PublicKeyCredentialCreationOptions::class.java) ?: TODO()
                val callingAppInfoOrigin = request.callingAppInfo.origin ?: TODO()
                val origin = Origin(callingAppInfoOrigin)
                val publicKeyCredentialCreationContext = PublicKeyCredentialCreationContext(origin)
                CoroutineScope(Dispatchers.Main).launch {
                    try{
                        val publicKeyCredential = webAuthnClient.create(publicKeyCredentialCreationOptions, publicKeyCredentialCreationContext)
                        val registrationResponseJson = objectConverter.jsonConverter.writeValueAsString(publicKeyCredential)
                        val result = Intent()
                        val createPublicKeyCredResponse = CreatePublicKeyCredentialResponse(registrationResponseJson)
                        PendingIntentHandler.setCreateCredentialResponse(result, createPublicKeyCredResponse)
//                        setResult(Activity.RESULT_OK, result)
                    }
                    catch (e: RuntimeException){
                        val result = Intent()
                        logger.error("", e)
                        PendingIntentHandler.setCreateCredentialException(result, CreateCredentialUnknownException())
                    }
                }
            }
        }

    }
}