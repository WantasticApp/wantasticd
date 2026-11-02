# Wantastic for Android

Native Kotlin app (Jetpack Compose) for Android 7.0+ (API 24): phones, tablets,
Android TV and ChromeOS. One universal APK for every CPU. Design and plan:
the "Wantastic for Android" canvas.

## What works in this build

- Sign-in by genkey claim: the phone makes its WireGuard key (X25519, kept in
  preferences encrypted with an Android Keystore key) and shows the same claim
  link as the desktop agent, as a QR code, "Log in with browser" and "Copy".
- The four tabs: Network, Peers, Console (the portal at console.wantastic.app),
  Settings (always-on VPN, battery optimization).
- The VPN permission flow and the system VPN service entry point.

The tunnel engine is not in this build yet: the screens say so rather than
show invented data. It plugs in behind `engine/Engine.kt`.

## Build

JDK 17 and the Android SDK (`ANDROID_HOME`):

```sh
./gradlew :app:testDebugUnitTest :app:assembleRelease
# app/build/outputs/apk/release/app-release.apk
```

Without `keystore.properties` the release build is signed with the debug key
(testing only).

## Release

Push a tag `android-vX.Y.Z` on this branch. CI tests, builds and signs the
APK, creates a GitHub release and uploads to R2:

- `https://get.wantastic.app/android/latest/wantastic-android.apk`
- `https://get.wantastic.app/android/X.Y.Z/wantastic-android-X.Y.Z.apk`
- `https://get.wantastic.app/android/latest/version`

### Signing key (once)

Every release must be signed with the same key, forever: Android refuses an
update signed with another one. Create it once and keep a copy offline:

```sh
keytool -genkeypair -v -keystore wantastic-release.keystore -alias wantastic \
  -keyalg RSA -keysize 4096 -validity 36500 \
  -dname "CN=Wantastic LLC, O=Wantastic LLC, C=US"
base64 -i wantastic-release.keystore | pbcopy   # macOS
```

Repository secrets: `ANDROID_KEYSTORE_B64` (the base64 above),
`ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` (`wantastic`),
`ANDROID_KEY_PASSWORD`. A tag without them fails instead of publishing a
debug-signed APK.
