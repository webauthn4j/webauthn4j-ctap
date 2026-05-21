import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id(libs.plugins.kotlin.jvm.get().pluginId)
    application
}

description = "Sample application demonstrating CTAP UHID bridge on Linux"

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
    mainClass.set("com.webauthn4j.ctap.uhid.sample.MainKt")
}

dependencies {
    implementation(project(":webauthn4j-ctap-uhid"))
    implementation(project(":webauthn4j-ctap-authenticator"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.slf4j.api)
    implementation(libs.logback.classic)
}
