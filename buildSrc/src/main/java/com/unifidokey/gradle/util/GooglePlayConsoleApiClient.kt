//package com.unifidokey.gradle.util
//
//import com.google.api.client.auth.oauth2.Credential
//import com.google.api.client.googleapis.apache.v2.GoogleApacheHttpTransport.newTrustedTransport
//import com.google.api.client.util.Preconditions
//import com.google.api.client.util.Strings
//import com.google.api.services.androidpublisher.AndroidPublisher
//import java.io.IOException
//import java.security.GeneralSecurityException
//import javax.annotation.Nullable
//import com.google.api.client.http.HttpTransport
//import com.google.api.client.json.JsonFactory
//import com.google.api.services.androidpublisher.AndroidPublisherScopes
//
//import com.google.api.client.googleapis.auth.oauth2.GoogleCredential
//import java.io.File
//import java.util.*
//
//object GooglePlayConsoleApiClient {
//
//    /**
//     * Track for uploading the apk, can be 'alpha', beta', 'production' or
//     * 'rollout'.
//     */
//    private const val TRACK_ALPHA = "alpha"
//    @JvmStatic
//    fun upload() {
//        init("", "")
//    }
//
//    /** Global instance of the JSON factory.  */
//    private val JSON_FACTORY: JsonFactory = TODO()
//
//    /** Global instance of the HTTP transport.  */
//    private val HTTP_TRANSPORT: HttpTransport? = null
//
//    private const val SRC_RESOURCES_KEY_P12 = "src/resources/key.p12"
//
//    @Throws(IOException::class, GeneralSecurityException::class)
//    fun init(
//        applicationName: String?,
//        @Nullable serviceAccountEmail: String
//    ): AndroidPublisher? {
//        Preconditions.checkArgument(
//            !Strings.isNullOrEmpty(applicationName),
//            "applicationName cannot be null or empty!"
//        )
//
//        // Authorization.
//        newTrustedTransport()
//        val credential: Credential = authorizeWithServiceAccount(serviceAccountEmail)
//
//        // Set up and return API client.
//        return AndroidPublisher.Builder(
//            HTTP_TRANSPORT, JSON_FACTORY, credential
//        ).setApplicationName(applicationName)
//            .build()
//    }
//
//    @Throws(GeneralSecurityException::class, IOException::class)
//    private fun authorizeWithServiceAccount(serviceAccountEmail: String): Credential {
//
//        // Build service account credential.
//        return GoogleCredential.Builder()
//            .setTransport(HTTP_TRANSPORT)
//            .setJsonFactory(JSON_FACTORY)
//            .setServiceAccountId(serviceAccountEmail)
//            .setServiceAccountScopes(
//                Collections.singleton(AndroidPublisherScopes.ANDROIDPUBLISHER)
//            )
//            .setServiceAccountPrivateKeyFromP12File(File(SRC_RESOURCES_KEY_P12))
//            .build()
//    }
//}