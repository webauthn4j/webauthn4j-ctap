plugins {
    id(libs.plugins.kotlin.jvm.get().pluginId)
}

description = "CTAP core library"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions.jvmTarget = JavaVersion.VERSION_11.toString()
    kotlinOptions.javaParameters = true
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
    api(libs.webauthn4j.core)

    implementation(libs.kotlinx.coroutines.core)

    // Third-party dependencies
    implementation(libs.slf4j.api)

    implementation(libs.jackson.module.kotlin)
    implementation(libs.jackson.dataformat.cbor)
    implementation(libs.jackson.datatype.jsr310)

    implementation(libs.bouncycastle.bcpkix.jdk15to18)
    implementation(libs.bouncycastle.bcprov.jdk15to18)

    // Test dependencies
    testImplementation(project(":webauthn4j-ctap-authenticator"))
    testImplementation(project(":webauthn4j-ctap-client"))

    testImplementation(libs.webauthn4j.test)
    testImplementation("ch.qos.logback:logback-classic")
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-inline")
    testImplementation(libs.mockito.kotlin)
    testImplementation("org.assertj:assertj-core")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test")
}

