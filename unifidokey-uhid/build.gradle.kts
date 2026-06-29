plugins {
    id(libs.plugins.kotlin.jvm.get().pluginId)
    id(libs.plugins.kotlin.plugin.allopen.get().pluginId)
    id(libs.plugins.quarkus.get().pluginId)
}

description = "Sample application demonstrating CTAP UHID bridge on Linux"

repositories {
    mavenCentral()
}

allOpen {
    annotation("jakarta.enterprise.context.ApplicationScoped")
}

dependencies {
    implementation(project(":webauthn4j-ctap-authenticator-uhid"))
    implementation(project(":webauthn4j-ctap-authenticator"))
    implementation(libs.kotlinx.coroutines.core)

    implementation(enforcedPlatform("io.quarkus.platform:quarkus-bom:${libs.versions.quarkus.get()}"))
    implementation("io.quarkus:quarkus-kotlin")
    implementation("io.quarkus:quarkus-arc")
    implementation("io.quarkus:quarkus-picocli")
}
