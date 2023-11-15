package com.unifidokey.driver.provider

import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.core.config.ConfigManager
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.GetAssertionConsentOptions
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentOptions
import com.webauthn4j.ctap.authenticator.UserConsentHandler
import com.webauthn4j.ctap.client.GetPublicKeyCredentialContext
import com.webauthn4j.ctap.client.CtapAuthenticatorHandle
import com.webauthn4j.ctap.client.GetAssertionsResponse
import com.webauthn4j.ctap.client.PublicKeyCredentialSelectionHandler
import com.webauthn4j.ctap.client.WebAuthnClient
import com.webauthn4j.ctap.client.transport.InProcessTransportAdaptor
import com.webauthn4j.data.AuthenticatorAssertionResponse
import com.webauthn4j.data.PublicKeyCredential
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory

class PasskeyCredentialProviderService : CredentialProviderService() {

    companion object{
        public val ACCOUNT_NAME = "Android Keystore"
        public val CREATE_PASSKEY = "com.unifidokey.provider.CREATE_PASSKEY"
        public val GET_PASSKEY = "com.unifidokey.provider.GET_PASSKEY"
    }

    private val logger = LoggerFactory.getLogger(PasskeyCredentialProviderService::class.java)

    private lateinit var unifidoKeyApplication: UnifidoKeyApplicationBase<*>
    private lateinit var configManager: ConfigManager
    private lateinit var objectConverter: ObjectConverter
    override fun onCreate() {
        unifidoKeyApplication = this.applicationContext as UnifidoKeyApplicationBase<*>
        configManager = unifidoKeyApplication.unifidoKeyComponent.configManager
        objectConverter = unifidoKeyApplication.unifidoKeyComponent.objectConverter
        super.onCreate()
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        try{
            val response: BeginCreateCredentialResponse = processCreateCredentialRequest(request)
            callback.onResult(response)
        }
        catch (e: RuntimeException){
            logger.error("Unexpected error is thrown onBeginCreateCredentialRequest", e)
            callback.onError(CreateCredentialUnknownException())
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        try {
            val response = processGetCredentialRequest(request)
            callback.onResult(response)
        } catch (e: GetCredentialException) {
            callback.onError(GetCredentialUnknownException())
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        TODO("Not yet implemented")
    }

    private fun processCreateCredentialRequest(request: BeginCreateCredentialRequest): BeginCreateCredentialResponse {
        when (request) {
            is BeginCreatePublicKeyCredentialRequest -> {
                return processCreatePublicKeyCredentialRequest(request)
            }
            else -> throw IllegalStateException("Unexpected ${request.type} is provided.")
        }
    }

    private fun processCreatePublicKeyCredentialRequest(request: BeginCreatePublicKeyCredentialRequest): BeginCreateCredentialResponse {
        // Adding two create entries - one for storing credentials to the 'Personal'
        // account, and one for storing them to the 'Family' account. These
        // accounts are local to this sample app only.
        val createEntries = listOf(
            CreateEntry(ACCOUNT_NAME, createPendingIntent(CREATE_PASSKEY), isAutoSelectAllowed = true)
        )
        return BeginCreateCredentialResponse(createEntries)
    }

    private fun processGetCredentialRequest(request: BeginGetCredentialRequest): BeginGetCredentialResponse? {

        val credentialEntries = request.beginGetCredentialOptions.flatMap {
            when(it){
                is BeginGetPublicKeyCredentialOption -> {
                    val publicKeyCredentialRequestOptions = objectConverter.jsonConverter.readValue(it.requestJson, PublicKeyCredentialRequestOptions::class.java)!!

                    val ctapAuthenticator = unifidoKeyApplication.unifidoKeyComponent.authenticatorService.ctapAuthenticator
                    ctapAuthenticator.userConsentHandler = object : UserConsentHandler {
                        override suspend fun consentMakeCredential(options: MakeCredentialConsentOptions): Boolean {
                            return true
                        }

                        override suspend fun consentGetAssertion(options: GetAssertionConsentOptions): Boolean {
                            return true
                        }
                    }
                    //TODO ctapAuthenticator.credentialSelectorSetting should be PLATFORM
                    val ctapAuthenticatorHandle = CtapAuthenticatorHandle(InProcessTransportAdaptor(ctapAuthenticator))
                    val webAuthnClient = WebAuthnClient(listOf(ctapAuthenticatorHandle), objectConverter)
                    val origin = Origin(request.callingAppInfo!!.origin!!)
                    val items = mutableListOf<GetAssertionsResponse.Assertion>();
                    runBlocking {
                        val publicKeyCredentialSelectionHandler = PublicKeyCredentialSelectionHandler { assertions ->
                            items.addAll(assertions)


                            return@PublicKeyCredentialSelectionHandler assertions.first()
                        }
                        val getPublicKeyCredentialContext = GetPublicKeyCredentialContext(origin, publicKeyCredentialSelectionHandler=publicKeyCredentialSelectionHandler)
                        webAuthnClient.get(publicKeyCredentialRequestOptions, getPublicKeyCredentialContext)
                    }

                    items.map{ item ->
                        val displayName = item.user?.displayName ?: item.user?.name ?: ""
                        val data = Bundle()
                        val publicKeyCredentialJSON = objectConverter.jsonConverter.writeValueAsString(publicKeyCredential)
                        data.putString("publicKeyCredentialJSON", publicKeyCredentialJSON)
                        PublicKeyCredentialEntry.Builder(
                            applicationContext,
                            displayName,
                            createPendingIntent(GET_PASSKEY, data),
                            it
                        ).build()
                    }

                }
                else -> throw IllegalStateException("Unexpected ${it.type} is provided.")
            }
        }
        return BeginGetCredentialResponse(credentialEntries)
    }

    private fun createPendingIntent(action: String, extra: Bundle? = null): PendingIntent {
        val intent = Intent(action).setPackage(this.packageName)
        if (extra != null) {
            intent.putExtra("CREDENTIAL_DATA", extra)
        }
        val requestCode = (1..9999).random()
        return PendingIntent.getActivity( //TODO: revisit: getBroadcast?
            applicationContext, requestCode,
            intent, (PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        )
    }


}