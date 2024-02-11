import com.unifidokey.gradle.util.PropertyUtil
import com.unifidokey.gradle.util.PublishAppBundleTask
import com.unifidokey.gradle.util.VersionCodeUtil
import org.jetbrains.kotlin.com.intellij.openapi.util.text.StringUtil

plugins {
    id("kotlin-android")
    id("com.google.devtools.ksp")
    id(libs.plugins.kotlin.kapt.get().pluginId)
    id(libs.plugins.androidx.navigation.safeargs.get().pluginId)
    id(libs.plugins.oss.licenses.plugins.get().pluginId)
    id(libs.plugins.google.services.get().pluginId)
    id("com.google.firebase.crashlytics")
}
//TODO
val unifidoKeyVersion = "0.9.0.RELEASE"

val unifidoKeyVersionCode = VersionCodeUtil.getVersionCodeFromVersionString(unifidoKeyVersion)

android {

    defaultConfig {
        compileSdk = 34 // Android 14.0
        minSdk = 34 // Android 14.0
        targetSdk = 34 // Android 14.0
        versionName = unifidoKeyVersion
        versionCode = unifidoKeyVersionCode

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_11
            targetCompatibility = JavaVersion.VERSION_11
        }
        kotlinOptions {
            jvmTarget = JavaVersion.VERSION_11.toString()
        }

    }
    signingConfigs {
        create("playstore") {
            PropertyUtil.load(rootProject, "secret.properties")
            storeFile = rootProject.file("unifidokey-upload-key.jks")
            storePassword = (System.getenv("KEYSTORE_PASS") ?: project.findProperty("unifidokey.keystorePass")) as String?
            keyAlias = (System.getenv("KEY_ALIAS") ?: project.findProperty("unifidokey.keyAlias")) as String?
            keyPassword = (System.getenv("KEY_PASS") ?: project.findProperty("unifidokey.keyPass")) as String?
        }
    }
    buildFeatures {
        dataBinding = true
        buildConfig = true
    }
    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
            isShrinkResources = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        getByName("release") {
            isMinifyEnabled = false   //TODO
            isShrinkResources = false //TODO
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    flavorDimensions.add("distribution")
    productFlavors {
        create("oss") {
            dimension = "distribution"

            applicationId = "com.unifidokey.oss"
            PropertyUtil.load(project, "src/oss/unifidokey.properties")
            buildConfigField("String", "ANDROID_SAFETY_NET_API_KEY", "${project.property("unifidokey.androidSafetyNetApiKey")}")
            isDefault = true

            //Disable mapping file upload because oss version don't want to rely on 3rd-party service(Firebase Crashlytics).
            configure<com.google.firebase.crashlytics.buildtools.gradle.CrashlyticsExtension> {
                mappingFileUploadEnabled = false
            }
        }
        create("playstore") {
            dimension = "distribution"

            applicationId = "com.unifidokey"
            PropertyUtil.load(project, "src/playstore/unifidokey.properties")
            buildConfigField("String", "ANDROID_SAFETY_NET_API_KEY", "${project.property("unifidokey.androidSafetyNetApiKey")}")
            if (rootProject.file("unifidokey-upload-key.jks").exists()) {
                signingConfig = signingConfigs.getByName("playstore")
            }
        }
    }
    testOptions {
        unitTests{
            isIncludeAndroidResources = true
        }
    }
    packaging {
        resources {
            excludes.add("README.txt")
        }
    }
    namespace = "com.unifidokey"
    lint{
//        lintConfig = file("lint.xml")
        baseline = file("lint-baseline.xml")
    }
}

// Disable Google Services Gradle Plugin on oss flavor not to enable Firebase backed features
androidComponents {
    onVariants(selector().withFlavor(Pair("distribution", "oss"))){ variantBuilder ->
        project.tasks.getByName("process" + StringUtil.capitalize(variantBuilder.name) + "GoogleServices").enabled = false
    }
}

tasks {
    register<PublishAppBundleTask>("publishAppBundle"){
        appBundle = file("${layout.buildDirectory.asFile.get().absolutePath}/outputs/bundle/playstoreRelease/unifidokey-handheld-playstore-release.aab")
        applicationName = "UnifidoKey"
        packageName = "com.unifidokey"
    }
    sonar {
        isSkipProject = true
    }
}



dependencies {

    // Kotlin
    implementation(libs.kotlin.stdlib.jdk8)
    implementation(libs.kotlinx.coroutines.core)

    // Project dependencies
    implementation(project(":unifidokey-core"))
    implementation(project(":webauthn4j-ctap-authenticator"))
    implementation(project(":webauthn4j-ctap-client"))

    // Android dependencies

    // Play services
    implementation(libs.play.services.oss.licenses)
    implementation(libs.play.services.fido)

    // AndroidX
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.legacy.support.v4)
    implementation(libs.androidx.preference)
    implementation(libs.androidx.recyclerview)
    implementation(libs.androidx.navigation.fragment)
    implementation(libs.androidx.navigation.ui)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.livedata)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.lifecycle.extensions)

    implementation(libs.androidx.credentials)


    implementation(libs.material)

    implementation(libs.dagger)
    implementation(libs.dagger.android)
    implementation(libs.dagger.android.support)

    //Firebase
    implementation("com.google.firebase:firebase-crashlytics")
    implementation("com.google.firebase:firebase-analytics")

    // Third Party dependencies
    implementation(libs.logback.android)
    implementation(libs.slf4j.api)
    implementation(libs.jackson.databind)
    implementation(libs.jackson.datatype.jsr310)
    implementation(libs.jackson.dataformat.cbor)
    implementation(libs.jackson.module.kotlin)


    // Annotation processor
    ksp(libs.androidx.room.compiler)
    kapt(libs.dagger.compiler)

    // test dependencies
    testImplementation(libs.junit)
    testImplementation(libs.mockito.core)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.androidx.test.ext.junit)
    testImplementation(libs.truth)
    testImplementation(libs.truth.java8.extension)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.logback.classic)

    kaptTest(libs.dagger.compiler)

    // Android test dependencies
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.espresso)
    androidTestImplementation(libs.truth)
    androidTestImplementation(libs.truth.java8.extension)
    androidTestImplementation(libs.android.support.annotations)

}
