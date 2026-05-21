import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id(libs.plugins.kotlin.jvm.get().pluginId)
    application
}

description = "Sample application demonstrating CTAP USB-IP server"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions{
        jvmTarget = JvmTarget.JVM_17
        javaParameters = true
    }
}

application {
    mainClass.set("com.webauthn4j.ctap.usbip.sample.MainKt")
}

dependencies {
    implementation(project(":webauthn4j-ctap-usbip"))
    implementation(project(":webauthn4j-ctap-authenticator"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.slf4j.api)
    implementation(libs.logback.classic)
}
