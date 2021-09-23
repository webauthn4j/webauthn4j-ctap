package com.unifidokey.gradle.util;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.AbstractInputStreamContent;
import com.google.api.client.http.FileContent;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.androidpublisher.AndroidPublisher;
import com.google.api.services.androidpublisher.AndroidPublisherScopes;
import com.google.api.services.androidpublisher.model.AppEdit;
import com.google.api.services.androidpublisher.model.Bundle;
import com.google.api.services.androidpublisher.model.LocalizedText;
import com.google.api.services.androidpublisher.model.Track;
import com.google.api.services.androidpublisher.model.TrackRelease;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.TaskAction;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PublishAppBundleTask extends DefaultTask {

    private static final Log log = LogFactory.getLog(PublishAppBundleTask.class);

    private static final String MIME_TYPE = "application/octet-stream";
    private static final String TRACK_INTERNAL = "internal";
    private static final String TRACK_ALPHA = "alpha";

    private String applicationName;
    private String packageName;
    private File appBundle;

    public PublishAppBundleTask(){
        getDependsOn().add("assembleRelease");
    }

    @TaskAction
    public void execute(){
        try {
            AndroidPublisher service = createAndroidPublisher(applicationName);
            AndroidPublisher.Edits edits = service.edits();

            String editId = createNewEdit(edits);
            Bundle bundle = uploadBundle(edits, editId);
            assignBundleToTrack(edits, editId, bundle, TRACK_INTERNAL);
            commitEdit(edits, editId);

        } catch (RuntimeException | IOException | GeneralSecurityException ex) {
            throw new GradleException("Exception was thrown while uploading app bundle to alpha track", ex);
        }
    }

    private String createNewEdit(AndroidPublisher.Edits edits) throws IOException {
        AndroidPublisher.Edits.Insert editRequest = edits.insert(packageName, null); //no content
        AppEdit edit = editRequest.execute();
        String editId = edit.getId();
        log.info(String.format("Created edit with id: %s", editId));
        return editId;
    }

    @SuppressWarnings("DefaultLocale")
    private Bundle uploadBundle(AndroidPublisher.Edits edits, String editId) throws IOException {
        AbstractInputStreamContent appBundleFile = new FileContent(MIME_TYPE, appBundle);
        AndroidPublisher.Edits.Bundles.Upload uploadRequest = edits
                .bundles()
                .upload(packageName,
                        editId,
                        appBundleFile);
        Bundle bundle = uploadRequest.execute();
        log.info(String.format("Version code %d has been uploaded", bundle.getVersionCode()));
         return bundle;
    }

    private void assignBundleToTrack(AndroidPublisher.Edits edits, String editId, Bundle bundle, String track) throws IOException {
        List<Long> apkVersionCodes = Collections.singletonList(Long.valueOf(bundle.getVersionCode()));
        AndroidPublisher.Edits.Tracks.Update updateTrackRequest = edits
                .tracks()
                .update(packageName,
                        editId,
                        track,
                        new Track()
                                .setReleases(
                                Collections.singletonList(
                                        new TrackRelease()
                                                .setName(bundle.getVersionCode().toString())
                                                .setVersionCodes(apkVersionCodes)
                                                .setStatus("completed"))));
        Track updatedTrack = updateTrackRequest.execute();
        log.info(String.format("Track %s has been updated.", updatedTrack.getTrack()));
    }

    private void commitEdit(AndroidPublisher.Edits edits, String editId) throws IOException {
        AndroidPublisher.Edits.Commit commitRequest = edits.commit(packageName, editId);
        AppEdit appEdit = commitRequest.execute();
        log.info(String.format("App edit with id %s has been committed", appEdit.getId()));
    }

    private AndroidPublisher createAndroidPublisher(String applicationName) throws IOException, GeneralSecurityException {
        NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        JsonFactory jsonFactory = new GsonFactory();

        // Set up and return API client.
        GoogleCredentials credentials = GoogleCredentials.getApplicationDefault().createScoped(Collections.singleton(AndroidPublisherScopes.ANDROIDPUBLISHER));
        HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(credentials);
        return new AndroidPublisher.Builder(httpTransport, jsonFactory, requestInitializer)
                .setApplicationName(applicationName)
                .build();
    }

    @Input
    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    @Input
    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    @InputFile
    public File getAppBundle() {
        return appBundle;
    }

    public void setAppBundle(Object appBundle) {
        this.appBundle = getProject().file(appBundle);
    }
}
