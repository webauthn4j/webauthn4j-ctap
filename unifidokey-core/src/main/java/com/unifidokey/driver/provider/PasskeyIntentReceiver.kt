package com.unifidokey.driver.provider

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.driver.provider.PasskeyCredentialProviderService.Companion.CREATE_PASSKEY
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.client.ClientProperty
import com.webauthn4j.ctap.client.CtapAuthenticatorHandle
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

                val ctapAuthenticatorHandle = CtapAuthenticatorHandle(InProcessTransportAdaptor(ctapAuthenticator))
                val webAuthnClient = WebAuthnClient(listOf(ctapAuthenticatorHandle))
                val publicKeyCredentialCreationOptions = objectConverter.jsonConverter.readValue(callingRequest.requestJson, PublicKeyCredentialCreationOptions::class.java) ?: TODO()
                val callingAppInfoOrigin = request.callingAppInfo.origin ?: TODO()
                val origin = Origin(callingAppInfoOrigin)
                val clientPIN = "" //TODO: Providing ClientPIN through clientProperty is really appropriate ClientProperty design?
                val clientProperty = ClientProperty(origin, clientPIN)
                CoroutineScope(Dispatchers.Main).launch {
                    try{
                        val publicKeyCredential = webAuthnClient.create(publicKeyCredentialCreationOptions, clientProperty)
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