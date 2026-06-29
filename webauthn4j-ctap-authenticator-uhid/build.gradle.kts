import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id(libs.plugins.kotlin.jvm.get().pluginId)
}

description = "CTAP UHID bridge library for Linux"

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

tasks {
    test {
        useJUnitPlatform()
    }
    jacocoTestReport {
        reports {
            xml.required.set(true)
        }
    }
}

dependencies {

    // Project dependencies
    api(project(":webauthn4j-ctap-authenticator"))

    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.slf4j.api)

    // Test dependencies
    testImplementation(platform(libs.junit.bom))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.junit.jupiter:junit-jupiter-params")

    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.logback.classic)
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.assertj.core)

    testImplementation(libs.jackson.module.kotlin)
    testImplementation(libs.jackson.dataformat.cbor)
    testImplementation(project(":webauthn4j-ctap-client"))
    testImplementation(libs.webauthn4j.test)
}
