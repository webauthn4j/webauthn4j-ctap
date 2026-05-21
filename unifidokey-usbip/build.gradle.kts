plugins {
    id(libs.plugins.kotlin.jvm.get().pluginId)
    id(libs.plugins.kotlin.plugin.allopen.get().pluginId)
    id(libs.plugins.quarkus.get().pluginId)
}

description = "Sample application demonstrating CTAP USB-IP server"

repositories {
    mavenLocal()
    mavenCentral()
}

allOpen {
    annotation("jakarta.enterprise.context.ApplicationScoped")
}

dependencies {
    implementation(project(":webauthn4j-ctap-authenticator-usbip"))
    implementation(project(":webauthn4j-ctap-authenticator"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.webauthn4j.metadata)

    implementation(enforcedPlatform("io.quarkus.platform:quarkus-bom:${libs.versions.quarkus.get()}"))
    implementation("io.quarkus:quarkus-kotlin")
    implementation("io.quarkus:quarkus-arc")
    implementation("io.quarkus:quarkus-picocli")
}
