# WebAuthn4J CTAP

[![Actions Status](https://github.com/webauthn4j/webauthn4j-ctap/workflows/CI/badge.svg)](https://github.com/webauthn4j/webauthn4j-ctap/actions)

WebAuthn4J CTAP is a Kotlin library implementing FIDO CTAP2. It can be run on OpenJDK and Android.

## Getting from Maven Central

If you are using Maven, just add the webauthn4j-ctap as a dependency:

```xml
<properties>
  ...
  <!-- Use the latest version whenever possible. -->
  <webauthn4jctap.version>0.1.1.RELEASE</webauthn4jctap.version>
  ...
</properties>

<dependencies>
  ...
  <!-- Ctap Authenticator -->
  <dependency>
    <groupId>com.webauthn4j</groupId>
    <artifactId>webauthn4j-ctap-authenticator</artifactId>
    <version>${webauthn4jctap.version}</version>
  </dependency>

  <!-- Ctap Client -->
  <dependency>
      <groupId>com.webauthn4j</groupId>
      <artifactId>webauthn4j-ctap-client</artifactId>
      <version>${webauthn4jctap.version}</version>
  </dependency>
  ...
</dependencies>
```

## Build from source

WebAuthn4J uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

### Prerequisites

- Java11 or later

### Checkout sources

```
git clone https://github.com/webauthn4j/webauthn4j-ctap
```

### Build all jars

```
./gradlew build
```

## License

WebAuthn4J CTAP is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).



## Contributing

Interested in helping out with WebAuthn4J? Great! Your participation in the community is much
appreciated!
Please feel free to open issues and send pull-requests.
