# Wantastic for Android

Native Kotlin app (Jetpack Compose) for Android 7.0+ (API 24): phones, tablets,
Android TV and ChromeOS. One universal APK for every CPU. Design and plan:
the "Wantastic for Android" canvas.

## What works in this build

- Sign-in by genkey claim: the phone makes its WireGuard key (X25519, kept in
  preferences encrypted with an Android Keystore key) and shows the same claim
  link as the desktop agent, as a QR code, "Log in" (approves inside the
  console mini app, no outside browser) and "Copy". The Go engine waits for
  the console's approval and the app moves on by itself.
- VPN access is requested at launch, once.
- The four tabs: Network, Peers, Console (the portal at console.wantastic.app),
  Settings (always-on VPN, battery optimization).
- The VPN permission flow and the system VPN service entry point.

The Go engine is `../mobile`, the agent's own code built with `gomobile bind`
into `app/libs/wantastic-engine.aar`; it has its own `go.mod`, so the agent's
dependencies never change for Android. So far it does the claim; the tunnel
is next, and the screens say so rather than show invented data.

## Build

JDK 17, the Android SDK (`ANDROID_HOME`) with the NDK (`ANDROID_NDK_HOME`),
and Go. Build the engine first, then the app:

```sh
(cd ../mobile && go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind &&
  gomobile bind -target=android/arm64,android/arm,android/amd64 -androidapi 24 \
    -javapkg app.wantastic -trimpath -ldflags="-s -w -extldflags=-Wl,-z,max-page-size=16384" -o ../android/app/libs/wantastic-engine.aar .)
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
