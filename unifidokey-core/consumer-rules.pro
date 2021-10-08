-keep ,includedescriptorclasses class org.slf4j.** { *; }
-keep ,includedescriptorclasses class ch.qos.logback.** { *; }
-keep ,includedescriptorclasses class com.fasterxml.jackson.** { *; }

-keep ,includedescriptorclasses class com.webauthn4j.data.** { *; }
-keep ,includedescriptorclasses class com.webauthn4j.ctap.core.data.** { *; }
-keep ,includedescriptorclasses class com.webauthn4j.ctap.authenticator.data.** { *; }

-keep ,includedescriptorclasses class com.unifidokey.core.config.** { *; }
-keep ,includedescriptorclasses class com.unifidokey.core.setting.** { *; }
-keep ,includedescriptorclasses class com.unifidokey.driver.persistence.dto.** { *; }
-keep ,includedescriptorclasses class com.unifidokey.driver.persistence.entity.** { *; }

-keep, allowobfuscation class com.webauthn4j.** { *; }
-keep, allowobfuscation class com.unifidokey.** { *; }

# enable for debugging
#-keepnames class ** { *; }
