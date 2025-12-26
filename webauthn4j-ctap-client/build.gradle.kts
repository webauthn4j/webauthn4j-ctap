import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id(libs.plugins.kotlin.jvm.get().pluginId)
}

description = "CTAP client library"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions{
        jvmTarget = JvmTarget.JVM_11
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
    api(project(":webauthn4j-ctap-core"))
    api(project(":webauthn4j-ctap-authenticator"))

    implementation(libs.kotlinx.coroutines.core)

    // Third-party dependencies
    implementation(libs.slf4j.api)

    implementation(libs.jackson.module.kotlin)
    implementation(libs.jackson.dataformat.cbor)
    implementation(libs.jackson.datatype.jsr310)

    implementation(libs.bouncycastle.bcpkix.jdk15to18)
    implementation(libs.bouncycastle.bcprov.jdk15to18)

    // Test dependencies
    testImplementation(platform(libs.junit.bom))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.junit.jupiter:junit-jupiter-params")

    testImplementation(libs.kotlinx.coroutines.test)

    testImplementation(libs.webauthn4j.test)

    testImplementation(libs.logback.classic)
    testImplementation(libs.mockito.core)
//    testImplementation(libs.mockito.inline)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.assertj.core)
}
