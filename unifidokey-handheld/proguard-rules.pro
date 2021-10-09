# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

-printusage build/outputs/unused.txt



-dontwarn "java.beans.Transient"
-dontwarn "javax.mail.Address"
-dontwarn "javax.mail.Authenticator"
-dontwarn "javax.mail.BodyPart"
-dontwarn "javax.mail.Message$RecipientType"
-dontwarn "javax.mail.Message"
-dontwarn "javax.mail.Multipart"
-dontwarn "javax.mail.Session"
-dontwarn "javax.mail.Transport"
-dontwarn "javax.mail.internet.AddressException"
-dontwarn "javax.mail.internet.InternetAddress"
-dontwarn "javax.mail.internet.MimeBodyPart"
-dontwarn "javax.mail.internet.MimeMessage"
-dontwarn "javax.mail.internet.MimeMultipart"
-dontwarn "javax.naming.NamingEnumeration"
-dontwarn "javax.naming.NamingException"
-dontwarn "javax.naming.directory.Attribute"
-dontwarn "javax.naming.directory.Attributes"
-dontwarn "javax.naming.directory.DirContext"
-dontwarn "javax.naming.directory.InitialDirContext"
-dontwarn "javax.naming.directory.SearchControls"
-dontwarn "javax.naming.directory.SearchResult"
-dontwarn "org.w3c.dom.bootstrap.DOMImplementationRegistry"
