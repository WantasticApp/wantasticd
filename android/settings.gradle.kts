pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "wantastic-android"
include(":app")
// The Kotlin tunnel engine: WireGuard, P2P, WUSP (app.wantastic.tunnel).
include(":tunnel")
