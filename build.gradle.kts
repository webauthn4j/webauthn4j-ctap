import org.gradle.jvm.tasks.Jar
import java.net.URI
import java.nio.charset.StandardCharsets

plugins {
    id("signing")
    id("org.gradle.maven-publish")

    id(libs.plugins.kotlin.jvm.get().pluginId) version libs.versions.kotlin
    id(libs.plugins.asciidoctor.get().pluginId) version libs.versions.asciidoctor
    id(libs.plugins.sonarqube.get().pluginId) version libs.versions.sonarqube
    id(libs.plugins.ksp.get().pluginId) version libs.versions.ksp apply false
}

val webAuthn4JCTAPVersion: String by project
val lastReleasedWebAuthn4JCTAPVersion: String by project

allprojects {

    group = "com.webauthn4j"
    version = webAuthn4JCTAPVersion

    configurations.configureEach {
        resolutionStrategy.cacheDynamicVersionsFor(0, TimeUnit.SECONDS)
    }
}

repositories {
    mavenCentral()
}


subprojects {
    apply(plugin = "signing")
    apply(plugin = "maven-publish")

    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "jacoco")

    repositories {
        google()
        mavenCentral()
        maven(url = "https://jitpack.io")
    }

    tasks.register("javadocJar", Jar::class) {
        dependsOn(tasks.named("javadoc"))
        archiveClassifier = "javadoc"
        from(tasks.named<Javadoc>("javadoc").get().destinationDir)
    }

    artifacts {
        archives(tasks.named("kotlinSourcesJar"))
    }

    fun getVariable(envName: String, propertyName: String): String?{
        return if (System.getenv(envName) != null && System.getenv(envName).isNotEmpty()) {
            System.getenv(envName)
        } else if (project.hasProperty(propertyName)) {
            project.property(propertyName) as String?
        } else {
            null
        }
    }

    val githubUrl = "https://github.com/webauthn4j/webauthn4j-ctap"
    val mavenCentralUser = getVariable("MAVEN_CENTRAL_USER", "mavenCentralUser")
    val mavenCentralPassword = getVariable("MAVEN_CENTRAL_PASSWORD", "mavenCentralPassword")
    val pgpSigningKey = getVariable("PGP_SIGNING_KEY", "pgpSigningKey")
    val pgpSigningKeyPassphrase = getVariable("PGP_SIGNING_KEY_PASSPHRASE", "pgpSigningKeyPassphrase")

    publishing {
        publications{
            create<MavenPublication>("standard") {
                from(components["java"])
                artifact(tasks.named("kotlinSourcesJar"))
                artifact(tasks.named("javadocJar"))

                // "Resolved versions" strategy is used to define dependency version because WebAuthn4J use dependencyManagement (BOM) feature
                // to define its dependency versions. Without "Resolved versions" strategy, version will not be exposed
                // to dependencies.dependency.version in POM file, and it cause warning in the library consumer environment.
                versionMapping {
                    usage("java-api") {
                        fromResolutionOf("runtimeClasspath")
                    }
                    usage("java-runtime") {
                        fromResolutionResult()
                    }
                }

                pom {
                    name = project.name
                    //description = project.description.toString() //TODO: this doesn't work. to be fixed. https://github.com/gradle/gradle/issues/12259
                    url = githubUrl
                    licenses {
                        license {
                            name = "The Apache Software License, Version 2.0"
                            url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                            distribution = "repo"
                        }
                    }
                    developers {
                        developer {
                            id = "ynojima"
                            name = "Yoshikazu Nojima"
                            email = "mail@ynojima.net"
                        }
                    }
                    scm {
                        url = githubUrl
                    }
                }
                pom.withXml{
                    asNode().appendNode("description", project.description) // workaround for https://github.com/gradle/gradle/issues/12259
                }
            }
        }

        repositories {
            maven {
                name = "mavenCentral"
                url = URI("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
                credentials {
                    username = "${mavenCentralUser}"
                    password = "${mavenCentralPassword}"
                }
            }
            maven {
                name = "snapshot"
                url = URI("https://oss.sonatype.org/content/repositories/snapshots")
                credentials {
                    username = "${mavenCentralUser}"
                    password = "${mavenCentralPassword}"
                }
            }
        }

        signing {
            useInMemoryPgpKeys(pgpSigningKey, pgpSigningKeyPassphrase)
            sign(publishing.publications["standard"])
        }

        tasks.withType(Sign::class.java).configureEach {
            onlyIf { pgpSigningKey != null && pgpSigningKeyPassphrase != null }
        }
        tasks.named("publishStandardPublicationToSnapshotRepository"){
            onlyIf{ webAuthn4JCTAPVersion.endsWith("-SNAPSHOT") }
        }
        tasks.named("publishStandardPublicationToMavenCentralRepository"){
            onlyIf{ !webAuthn4JCTAPVersion.endsWith("-SNAPSHOT") }
        }


    }

}

tasks.register("updateVersionsInDocuments"){
    group = "documentation"

    val regex = Regex("""<webauthn4jctap.version>.*</webauthn4jctap.version>""")
    val replacement = "<webauthn4jctap.version>$lastReleasedWebAuthn4JCTAPVersion</webauthn4jctap.version>"

    val files = arrayOf(file("README.md"))
    files.forEach { file ->
        val updated = file.readText(StandardCharsets.UTF_8).replaceFirst(regex, replacement)
        file.writeText(updated, StandardCharsets.UTF_8)
    }
}

tasks.register<JavaExec>("generateReleaseNote") {
    group = "documentation"
    classpath = files("gradle/lib/github-release-notes-generator.jar")

    args(webAuthn4JCTAPVersion, file("build/release-note.md").absolutePath, "--spring.config.location=file:" + file("github-release-notes-generator.yml").absolutePath)
}



sonarqube {
    properties {
        property("sonar.projectKey", "webauthn4j-ctap")
        property("sonar.issue.ignore.multicriteria", "e1,e2,e3")
        property("sonar.issue.ignore.multicriteria.e1.ruleKey", "java:S110")
        property("sonar.issue.ignore.multicriteria.e1.resourceKey", "**/*.java")
        property("sonar.issue.ignore.multicriteria.e2.ruleKey", "java:S1452")
        property("sonar.issue.ignore.multicriteria.e2.resourceKey", "**/*.java")
        property("sonar.issue.ignore.multicriteria.e3.ruleKey", "common-java:DuplicatedBlocks")
        property("sonar.issue.ignore.multicriteria.e3.resourceKey", "**/*.java")
    }
}

