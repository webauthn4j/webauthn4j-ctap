import com.webauthn4j.gradle.BuildUtils
import com.webauthn4j.gradle.VersionUtils
import org.gradle.jvm.tasks.Jar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jreleaser.model.Active
import java.net.URI
import java.nio.charset.StandardCharsets

plugins {
    id("signing")
    id("org.gradle.maven-publish")
    id("java-library")
    id("jacoco")

    id(libs.plugins.kotlin.jvm.get().pluginId) version libs.versions.kotlin apply false
    id(libs.plugins.asciidoctor.get().pluginId) version libs.versions.asciidoctor
    id(libs.plugins.sonarqube.get().pluginId) version libs.versions.sonarqube
    id(libs.plugins.jreleaser.get().pluginId) version libs.versions.jreleaser
    id(libs.plugins.ksp.get().pluginId) version libs.versions.ksp apply false
}

private val webAuthn4JCTAPVersion: String by project
private val isSnapshot: Boolean = (findProperty("isSnapshot") as? String)?.toBoolean() ?: true
private val effectiveVersion = VersionUtils.getEffectiveVersion(isSnapshot, webAuthn4JCTAPVersion)

allprojects {

    group = "com.webauthn4j"
    version = effectiveVersion

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

    apply(plugin = "java-library")
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "jacoco")
    apply(plugin = "org.jreleaser")
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

    val githubUrl = "https://github.com/webauthn4j/webauthn4j-ctap"
    val mavenCentralUser = BuildUtils.getVariable(project, "MAVEN_CENTRAL_USER", "mavenCentralUser")
    val mavenCentralPassword = BuildUtils.getVariable(project, "MAVEN_CENTRAL_PASSWORD", "mavenCentralPassword")
    val pgpSigningKey = BuildUtils.getVariable(project, "PGP_SIGNING_KEY", "pgpSigningKey")
    val pgpSigningKeyPassphrase = BuildUtils.getVariable(project, "PGP_SIGNING_KEY_PASSPHRASE", "pgpSigningKeyPassphrase")

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
                name = "localStaging"
                url = layout.buildDirectory.dir("local-staging").get().asFile.toURI()
            }
            maven {
                name = "snapshot"
                url = URI("https://central.sonatype.com/repository/maven-snapshots/")
                credentials {
                    username = mavenCentralUser
                    password = mavenCentralPassword
                }
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
        onlyIf{ isSnapshot }
    }

    jreleaser {
        project {
            authors.set(listOf("Yoshikazu Nojima"))
            license = "Apache-2.0"
            links {
                homepage = githubUrl
            }
            version = effectiveVersion
        }

        release{
            github{
                token.set("dummy")
                skipRelease = true
                skipTag = true
            }
        }

        deploy {
            maven {
                mavenCentral {
                    this.register("mavenCentral"){
                        active = Active.RELEASE
                        sign = false // artifacts are signed by gradle native feature. signing by jreleaser is not required.
                        username = mavenCentralUser
                        password = mavenCentralPassword
                        url = "https://central.sonatype.com/api/v1/publisher/"
                        stagingRepository(layout.buildDirectory.dir("local-staging").get().asFile.absolutePath)
                    }
                }
            }
        }
    }

}


tasks.register("bumpPatchVersion"){
    group = "documentation"

    doLast{
        val regex = Regex("""^webAuthn4JCTAPVersion=.*$""", RegexOption.MULTILINE)
        val bumpedVersion = VersionUtils.bumpPatchVersion(webAuthn4JCTAPVersion)
        val replacement = "webAuthn4JCTAPVersion=${bumpedVersion}"

        val file = file("gradle.properties")
        val original = file.readText(StandardCharsets.UTF_8)
        if (!regex.containsMatchIn(original)) {
            throw GradleException("webAuthn4JCTAPVersion property not found in gradle.properties")
        }
        val updated = original.replaceFirst(regex, replacement)
        file.writeText(updated, StandardCharsets.UTF_8)
    }
}

tasks.register("updateVersionsInDocuments"){
    group = "documentation"

    doLast{
        val regex = Regex("""<webauthn4jctap.version>.*</webauthn4jctap.version>""")
        val replacement = "<webauthn4jctap.version>${effectiveVersion}</webauthn4jctap.version>"

        val files = arrayOf(file("README.md"))
        files.forEach { file ->
            val updated = file.readText(StandardCharsets.UTF_8).replaceFirst(regex, replacement)
            file.writeText(updated, StandardCharsets.UTF_8)
        }
    }
}

tasks.register("switchToSnapshot"){
    group = "documentation"

    doLast{
        val regex = Regex("""^isSnapshot=.*$""", RegexOption.MULTILINE)
        val replacement = "isSnapshot=true"

        val file = file("gradle.properties")
        val original = file.readText(StandardCharsets.UTF_8)
        if (!regex.containsMatchIn(original)) {
            throw GradleException("isSnapshot property not found in gradle.properties")
        }
        val updated = original.replaceFirst(regex, replacement)
        file.writeText(updated, StandardCharsets.UTF_8)
    }
}

tasks.register("switchToRelease"){
    group = "documentation"

    doLast{
        val regex = Regex("""^isSnapshot=.*$""", RegexOption.MULTILINE)
        val replacement = "isSnapshot=false"

        val file = file("gradle.properties")
        val original = file.readText(StandardCharsets.UTF_8)
        if (!regex.containsMatchIn(original)) {
            throw GradleException("isSnapshot property not found in gradle.properties")
        }
        val updated = original.replaceFirst(regex, replacement)
        file.writeText(updated, StandardCharsets.UTF_8)
    }
}

tasks.register<JavaExec>("generateReleaseNote") {
    group = "documentation"
    classpath = files("gradle/lib/github-release-notes-generator.jar")

    args(effectiveVersion, file("build/release-note.md").absolutePath, "--spring.config.location=file:" + file("github-release-notes-generator.yml").absolutePath)
}

sonar {
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
