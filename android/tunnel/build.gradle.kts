// app.wantastic.tunnel: Wantastic's tunnel engine in Kotlin (WireGuard with
// Wantastic's P2P, WUSP and exit-node extensions), independent of the UI.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.wantastic.tunnel"
    compileSdk = 36
    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
        // The agents' shared signing key, read from the Go agent's source at
        // build time so the repository keeps a single copy of it.
        val authGo = rootProject.file("../internal/auth/auth.go").readText()
        val secret = Regex("""SharedSecret\s*=\s*"([^"]+)"""").find(authGo)?.groupValues?.get(1)
            ?: error("SharedSecret not found in internal/auth/auth.go")
        buildConfigField("String", "AGENT_SHARED_SECRET", "\"$secret\"")
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

dependencies {
    implementation("com.google.crypto.tink:tink-android:1.15.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    testImplementation("junit:junit:4.13.2")
    // The real org.json: Android's is a stub in plain JVM unit tests.
    testImplementation("org.json:json:20240303")
}
