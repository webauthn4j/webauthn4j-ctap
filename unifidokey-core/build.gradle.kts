plugins {
    id("kotlin-android")
    id("com.google.devtools.ksp")
    id(libs.plugins.kotlin.kapt.get().pluginId)
}

android {

    defaultConfig {
        compileSdk = 34 // Android 14.0
        minSdk = 34 // Android 14.0

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_11
            targetCompatibility = JavaVersion.VERSION_11
        }
        kotlinOptions {
            jvmTarget = JavaVersion.VERSION_11.toString()
        }

        //ProGuard
        consumerProguardFiles("consumer-rules.pro")

    }
    buildFeatures {
        dataBinding = true
        buildConfig = true
    }
    packaging {
        resources {
            excludes.add("README.txt")
        }
    }
    namespace = "com.unifidokey.core"

    lint{
        baseline = file("lint-baseline.xml")
    }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

description = "Provides core functionality, which is specific to UnifidoKey but independent from Android SDK"


tasks {
    sonar {
        isSkipProject = true
    }
    withType<org.jetbrains.kotlin.gradle.tasks.KaptGenerateStubs>().configureEach{
        kotlinOptions{
            jvmTarget= JavaVersion.VERSION_11.toString()
        }
    }
}


dependencies {

    // Kotlin
    implementation(libs.kotlin.stdlib.jdk8)

    // project dependencies
    implementation(libs.webauthn4j.core)
    implementation(project(":webauthn4j-ctap-authenticator"))
    implementation(project(":webauthn4j-ctap-client"))

    // Third Party dependencies
    implementation(libs.slf4j.api)

    implementation(libs.jackson.databind)
    implementation(libs.jackson.datatype.jsr310)
    implementation(libs.jackson.dataformat.cbor)
    implementation(libs.jackson.module.kotlin)

    // Android dependencies

    // Play services
    implementation(libs.play.services.auth)
    implementation(libs.play.services.fido)
    implementation(libs.play.services.safetynet)

    // AndroidX
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.legacy.support.v4)
    implementation(libs.androidx.preference)
    implementation(libs.androidx.biometric)

    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.livedata)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.lifecycle.extensions)

    implementation(libs.androidx.credentials)

    implementation(libs.dagger)
    implementation(libs.dagger.android)
    implementation(libs.dagger.android.support)

    //Firebase
    implementation("com.google.firebase:firebase-crashlytics")
    implementation("com.google.firebase:firebase-analytics")

    // Annotation processor
    ksp(libs.androidx.room.compiler)
    kapt(libs.dagger.compiler)

    // Test dependencies
    testImplementation(libs.junit)
    testImplementation(libs.mockito.core)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.androidx.test.ext.junit)
    testImplementation(libs.truth)
    testImplementation(libs.truth.java8.extension)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.robolectric)
    testImplementation(libs.logback.classic)

    // Android test dependencies
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.espresso)
    androidTestImplementation(libs.truth)
    androidTestImplementation(libs.truth.java8.extension)
    androidTestImplementation(libs.android.support.annotations)

}

