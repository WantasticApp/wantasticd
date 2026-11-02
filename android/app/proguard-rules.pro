# Tink and security-crypto reflect on protobuf-lite classes.
-keep class com.google.crypto.tink.** { *; }
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
# The Go engine: gomobile looks these up by name over JNI.
-keep class go.** { *; }
-keep class app.wantastic.mobile.** { *; }
