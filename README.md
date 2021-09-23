# WebAuthn4J UnifidoKey

![Home screen](docs/images/home.png)
![Registration screen](./docs/images/registration.png)

[![Actions Status](https://github.com/webauthn4j/UnifidoKey/workflows/CI/badge.svg)](https://github.com/webauthn4j/unifidokey/actions)

WebAuthn4J UnifidoKey is an Android app which act as a WebAuthn security key.
No longer need to buy an expensive physical security key and carry it everyday. 
Just install the UnifidoKey app to your smartphone, and enjoy secure and convenient authentication.

## Install

Install from Google Play Store.

## Documentation

* [User Guide(en)](https://docs.unifidokey.com/en)
* [User Guide(ja)](https://docs.unifidokey.com/ja)

## Build from source

UnifidoKey has two product-flavors:

* OSS flavor
  * OSS developers can build without friction
* Play Store flavor
  * OSS flavor + Firebase crashlytics + App signing

### product-flavor: OSS

Build Apk for local debug

```
./gradlew assembleOssRelease
```

### product-flavor: Play Store

Build App Bundle to be published to Play store

```
cd <project root>

# place unifidokey-upload-key.jks which contains upload key
cp <somewhere>/unifidokey-upload-key.jks ./unifidokey-upload-key.jks

# export following environment variables:
export KEYSTORE_PASS : ${{ secrets.KEYSTORE_PASS  }}
export KEY_ALIAS : ${{ secrets.KEY_ALIAS  }}
export KEY_PASS : ${{ secrets.KEY_PASS  }}

./gradlew bundlePlaystoreRelease
```

### Build configuration

`unifidokey.androidSafetyNetApiKey` gradle property need to be set via `local.properties` file or `-Punifidokey.androidSafetyNetApiKey=<value>` command line argument for gradle execution.

## License

WebAuthn4J UnifidoKey is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).

## Contributing

Interested in helping out with WebAuthn4J? Great! Your participation in the community is much appreciated!
Please feel free to open issues and send pull-requests.
