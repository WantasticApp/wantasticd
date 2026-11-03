# Tink and security-crypto reflect on protobuf-lite classes.
-keep class com.google.crypto.tink.** { *; }
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
# The Go engine: gomobile looks these up by name over JNI.
-keep class go.** { *; }
-keep class app.wantastic.mobile.** { *; }
# Credential Manager finds its Play services provider by name.
-if class androidx.credentials.CredentialManager
-keep class androidx.credentials.playservices.** { *; }
# JSch loads its ciphers, key exchanges and signatures by class name.
-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**
