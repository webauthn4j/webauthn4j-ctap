import com.unifidokey.gradle.util.PropertyUtil
import com.unifidokey.gradle.util.PublishAppBundleTask
import com.unifidokey.gradle.util.VersionCodeUtil
import org.jetbrains.kotlin.com.intellij.openapi.util.text.StringUtil

plugins {
    id("kotlin-android")
    id("kotlin-kapt")
    id("androidx.navigation.safeargs")
    id("com.google.android.gms.oss-licenses-plugin")
    id("com.google.gms.google-services")
    id("com.google.firebase.crashlytics")
}
//TODO
val unifidoKeyVersion = "0.8.2-SNAPSHOT"

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
//        create("playstore") {
//            PropertyUtil.load(rootProject, "secret.properties")
//            storeFile = rootProject.file("unifidokey-upload-key.jks")
//            storePassword = (System.getenv("KEYSTORE_PASS") ?: project.findProperty("unifidokey.keystorePass")) as String
//            keyAlias = (System.getenv("KEY_ALIAS") ?: project.findProperty("unifidokey.keyAlias")) as String
//            keyPassword = (System.getenv("KEY_PASS") ?: project.findProperty("unifidokey.keyPass")) as String
//        }
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
//            if (rootProject.file("unifidokey-upload-key.jks").exists()) {
//                signingConfig = signingConfigs.getByName("playstore")
//            }
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
    //TODO
    val daggerVersion = "2.48.1"
    val roomVersion = "2.4.3"

    // Kotlin
    implementation(libs.kotlin.stdlib.jdk8)
    implementation(libs.kotlinx.coroutines.core)

    // Project dependencies
    implementation(project(":unifidokey-core"))
    implementation(project(":webauthn4j-ctap-authenticator"))
    implementation(project(":webauthn4j-ctap-client"))

    // Third Party dependencies
    implementation("com.github.tony19:logback-android")
    implementation("org.slf4j:slf4j-api")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor")

    // Android dependencies
    implementation("androidx.room:room-runtime")

    // Play services
    implementation("com.google.android.gms:play-services-oss-licenses")
    implementation("com.google.android.gms:play-services-fido")

    // AndroidX
    implementation("androidx.appcompat:appcompat")
    implementation("androidx.constraintlayout:constraintlayout")
    implementation("androidx.biometric:biometric")
    implementation("androidx.legacy:legacy-support-v4")
    implementation("androidx.preference:preference")
    implementation("androidx.recyclerview:recyclerview")
    implementation("androidx.navigation:navigation-fragment")
    implementation("androidx.navigation:navigation-ui")
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.livedata)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation("androidx.lifecycle:lifecycle-extensions")

    implementation(libs.androidx.credentials)


    implementation("com.google.android.material:material")

    implementation("com.google.dagger:dagger")
    implementation("com.google.dagger:dagger-android")
    implementation("com.google.dagger:dagger-android-support")

    //Firebase
    implementation("com.google.firebase:firebase-crashlytics")
    implementation("com.google.firebase:firebase-analytics")


    // Annotation processor
    kapt("com.google.dagger:dagger-compiler:$daggerVersion")
    kapt("androidx.room:room-compiler:$roomVersion")

    // test dependencies
    testImplementation("junit:junit")
    testImplementation("org.mockito:mockito-core")
    testImplementation("androidx.test:core")
    testImplementation("androidx.test.ext:junit")
    testImplementation("com.google.truth:truth")
    testImplementation("com.google.truth.extensions:truth-java8-extension")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test")
    testImplementation("org.robolectric:robolectric")

    kaptTest("com.google.dagger:dagger-compiler:$daggerVersion")
    kaptTest("androidx.room:room-compiler:$roomVersion")

    // Android test dependencies
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.espresso)
    androidTestImplementation(libs.truth)
    androidTestImplementation(libs.truth.java8.extension)
    androidTestImplementation(libs.android.support.annotations)

}