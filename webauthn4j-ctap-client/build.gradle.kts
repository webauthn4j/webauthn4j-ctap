plugins {
    id("org.jetbrains.kotlin.jvm")
}

description = "CTAP client library"

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
    api(project(":webauthn4j-ctap-core"))
    api(project(":webauthn4j-ctap-authenticator"))

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core")

    // Third-party dependencies
    implementation("org.slf4j:slf4j-api")

    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")

    implementation("org.bouncycastle:bcpkix-jdk15to18")
    implementation("org.bouncycastle:bcprov-jdk15to18")

    // Test dependencies
    testImplementation("com.github.webauthn4j.webauthn4j:webauthn4j-test")
    testImplementation("ch.qos.logback:logback-classic")
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-inline")
    testImplementation("org.mockito.kotlin:mockito-kotlin")
    testImplementation("org.assertj:assertj-core")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test")
}
