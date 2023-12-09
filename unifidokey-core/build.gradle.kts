plugins {
    id("kotlin-android")
    id("kotlin-kapt")
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


        javaCompileOptions {
            annotationProcessorOptions {
                arguments["room.schemaLocation"] = "$projectDir/schemas"
            }
        }
        //ProGuard
        consumerProguardFiles("consumer-rules.pro")

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
    implementation("com.github.webauthn4j.webauthn4j:webauthn4j-core")
    implementation(project(":webauthn4j-ctap-authenticator"))
    implementation(project(":webauthn4j-ctap-client"))

    // Third Party dependencies
    implementation("org.slf4j:slf4j-api")

    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")

    // Android dependencies

    // Play services
    implementation("com.google.android.gms:play-services-auth")
    implementation("com.google.android.gms:play-services-fido")
    implementation("com.google.android.gms:play-services-safetynet")

    // AndroidX
    implementation("androidx.core:core-ktx")
    implementation("androidx.room:room-runtime")
    implementation("androidx.appcompat:appcompat")
    implementation("androidx.legacy:legacy-support-v4")
    implementation("androidx.preference:preference")
    implementation("androidx.biometric:biometric")

    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.livedata)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation("androidx.lifecycle:lifecycle-extensions")

    implementation(libs.androidx.credentials)

    implementation("com.google.dagger:dagger")
    implementation("com.google.dagger:dagger-android")
    implementation("com.google.dagger:dagger-android-support")

    //Firebase
    implementation("com.google.firebase:firebase-crashlytics")
    implementation("com.google.firebase:firebase-analytics")

    // Annotation processor
    kapt(libs.dagger.compiler)
    kapt(libs.androidx.room.compiler)

    // Test dependencies
    testImplementation("ch.qos.logback:logback-classic")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test")
    testImplementation("junit:junit")
    testImplementation("org.mockito:mockito-core")
    testImplementation("androidx.test:core:")
    testImplementation("androidx.test.ext:junit")
    testImplementation("com.google.truth:truth")
    testImplementation("com.google.truth.extensions:truth-java8-extension")
    testImplementation("org.robolectric:robolectric")

    kaptTest(libs.dagger.compiler)
    kaptTest(libs.androidx.room.compiler)

    // Android test dependencies
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.espresso)
    androidTestImplementation(libs.truth)
    androidTestImplementation(libs.truth.java8.extension)
    androidTestImplementation(libs.android.support.annotations)

}

