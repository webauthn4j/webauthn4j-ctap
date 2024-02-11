package com.unifidokey.gradle.util

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport
import com.google.api.client.http.AbstractInputStreamContent
import com.google.api.client.http.FileContent
import com.google.api.client.http.HttpRequestInitializer
import com.google.api.client.json.JsonFactory
import com.google.api.client.json.gson.GsonFactory
import com.google.api.services.androidpublisher.AndroidPublisher
import com.google.api.services.androidpublisher.AndroidPublisherScopes
import com.google.api.services.androidpublisher.model.Bundle
import com.google.api.services.androidpublisher.model.Track
import com.google.api.services.androidpublisher.model.TrackRelease
import com.google.auth.http.HttpCredentialsAdapter
import com.google.auth.oauth2.GoogleCredentials
import org.apache.commons.logging.LogFactory
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException

open class PublishAppBundleTask : DefaultTask() {
    @Input
    var applicationName: String? = null

    @Input
    var packageName: String? = null

    @InputFile
    var appBundle: File? = null

    init {
        dependsOn.add("assembleRelease")
    }

    @TaskAction
    fun execute() {
        try {
            val service = createAndroidPublisher(applicationName)
            val edits = service.edits()
            val editId = createNewEdit(edits)
            val bundle = uploadBundle(edits, editId)
            assignBundleToTrack(edits, editId, bundle, TRACK_INTERNAL)
            commitEdit(edits, editId)
        } catch (ex: RuntimeException) {
            throw GradleException(
                "Exception was thrown while uploading app bundle to alpha track",
                ex
            )
        } catch (ex: IOException) {
            throw GradleException(
                "Exception was thrown while uploading app bundle to alpha track",
                ex
            )
        } catch (ex: GeneralSecurityException) {
            throw GradleException(
                "Exception was thrown while uploading app bundle to alpha track",
                ex
            )
        }
    }

    @Throws(IOException::class)
    private fun createNewEdit(edits: AndroidPublisher.Edits): String {
        val editRequest = edits.insert(packageName, null) //no content
        val edit = editRequest.execute()
        val editId = edit.id
        log.info(String.format("Created edit with id: %s", editId))
        return editId
    }

    @Throws(IOException::class)
    private fun uploadBundle(edits: AndroidPublisher.Edits, editId: String): Bundle {
        val appBundleFile: AbstractInputStreamContent = FileContent(MIME_TYPE, appBundle)
        val uploadRequest = edits
            .bundles()
            .upload(
                packageName,
                editId,
                appBundleFile
            )
        val bundle = uploadRequest.execute()
        log.info(String.format("Version code %d has been uploaded", bundle.versionCode))
        return bundle
    }

    @Throws(IOException::class)
    private fun assignBundleToTrack(
        edits: AndroidPublisher.Edits,
        editId: String,
        bundle: Bundle,
        track: String
    ) {
        val apkVersionCodes = listOf(java.lang.Long.valueOf(bundle.versionCode.toLong()))
        val updateTrackRequest = edits
            .tracks()
            .update(
                packageName,
                editId,
                track,
                Track()
                    .setReleases(
                        listOf(
                            TrackRelease()
                                .setName(bundle.versionCode.toString())
                                .setVersionCodes(apkVersionCodes)
                                .setStatus("completed")
                        )
                    )
            )
        val updatedTrack = updateTrackRequest.execute()
        log.info(String.format("Track %s has been updated.", updatedTrack.track))
    }

    @Throws(IOException::class)
    private fun commitEdit(edits: AndroidPublisher.Edits, editId: String) {
        val commitRequest = edits.commit(packageName, editId)
        val appEdit = commitRequest.execute()
        log.info(String.format("App edit with id %s has been committed", appEdit.id))
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    private fun createAndroidPublisher(applicationName: String?): AndroidPublisher {
        val httpTransport = GoogleNetHttpTransport.newTrustedTransport()
        val jsonFactory: JsonFactory = GsonFactory()

        // Set up and return API client.
        val credentials = GoogleCredentials.getApplicationDefault().createScoped(
            setOf(
                AndroidPublisherScopes.ANDROIDPUBLISHER
            )
        )
        val requestInitializer: HttpRequestInitializer = HttpCredentialsAdapter(credentials)
        return AndroidPublisher.Builder(httpTransport, jsonFactory, requestInitializer)
            .setApplicationName(applicationName)
            .build()
    } //    @Input

    //    public String getApplicationName() {
    //        return applicationName;
    //    }
    //
    //    public void setApplicationName(String applicationName) {
    //        this.applicationName = applicationName;
    //    }
    //
    //    @Input
    //    public String getPackageName() {
    //        return packageName;
    //    }
    //
    //    public void setPackageName(String packageName) {
    //        this.packageName = packageName;
    //    }
    //
    //    @InputFile
    //    public File getAppBundle() {
    //        return appBundle;
    //    }
    //
    //    public void setAppBundle(Object appBundle) {
    //        this.appBundle = getProject().file(appBundle);
    //    }
    companion object {
        private val log = LogFactory.getLog(
            PublishAppBundleTask::class.java
        )
        private const val MIME_TYPE = "application/octet-stream"
        private const val TRACK_INTERNAL = "internal"
        private const val TRACK_ALPHA = "alpha"
    }
}