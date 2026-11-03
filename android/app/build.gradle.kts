import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    // Open-source notices: the license of every library, generated at build time.
    id("com.mikepenz.aboutlibraries.plugin")
}

// CI passes the release version (android-v1.2.3 -> 1.2.3) and a build number.
val appVersionName = (findProperty("appVersionName") as String?) ?: "0.1.0-dev"
val appVersionCode = ((findProperty("appVersionCode") as String?) ?: "1").toInt()

// Release signing comes from CI secrets; without them the release build is
// signed with the debug key so it still installs for testing.
val signingProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "app.wantastic.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.wantastic.android"
        minSdk = 24
        targetSdk = 36
        versionCode = appVersionCode
        versionName = appVersionName
    }

    signingConfigs {
        if (signingProps.containsKey("storeFile")) {
            create("release") {
                storeFile = rootProject.file(signingProps.getProperty("storeFile"))
                storePassword = signingProps.getProperty("storePassword")
                keyAlias = signingProps.getProperty("keyAlias")
                keyPassword = signingProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    // go-licenses.json from mobile/cmd/golicenses, generated with the engine.
    sourceSets["main"].assets.srcDir("libs/assets")

    // One universal APK for every CPU (arm64, armv7, x86_64, x86).
    splits { abi { isEnable = false } }

    // Two stores, one app. Google Play only allows updates through Play, so
    // "play" updates with Play's in-app updates (Play ships them as patches);
    // "direct" (get.wantastic.app) updates itself with binary patches.
    flavorDimensions += "store"
    productFlavors {
        create("play") {
            dimension = "store"
            buildConfigField("boolean", "SELF_UPDATE", "false")
        }
        create("direct") {
            dimension = "store"
            buildConfigField("boolean", "SELF_UPDATE", "true")
        }
    }
}

aboutLibraries {
    // Only what ships: no network lookups at build time.
    offlineMode = true
}

dependencies {
    // The Go engine, built from ../mobile by `gomobile bind` (see android/README.md).
    implementation(files("libs/wantastic-engine.aar"))
    val composeBom = platform("androidx.compose:compose-bom:2025.05.01")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.google.crypto.tink:tink-android:1.15.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    // The console channel (websocket) and its HTTP endpoints.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // Passkeys (Credential Manager; Play services provides them on Android 13 and older).
    implementation("androidx.credentials:credentials:1.5.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.5.0")
    implementation("com.mikepenz:aboutlibraries-core:12.2.4")
    "playImplementation"("com.google.android.play:app-update-ktx:2.1.0")
    // Play's library brings an old Fragment that breaks registerForActivityResult.
    "playImplementation"("androidx.fragment:fragment-ktx:1.8.9")
    // bzip2 for bsdiff patches (direct updates only).
    "directImplementation"("org.apache.commons:commons-compress:1.28.0")
    // Ships the Compose baseline profiles so first launch is compiled, not interpreted.
    implementation("androidx.profileinstaller:profileinstaller:1.4.1")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.compose.ui:ui-tooling-preview")

    testImplementation("junit:junit:4.13.2")
}
