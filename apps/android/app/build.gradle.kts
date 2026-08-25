plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.resilient.messenger"
    compileSdk = 36
    defaultConfig {
        applicationId = "org.resilient.messenger"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures {
        buildConfig = true
        compose = true
    }
    buildTypes { release { isMinifyEnabled = true } }
}

dependencies {
    // 2026.08.00 requires the API 37 preview SDK; stay on the latest API 36-compatible stable BOM.
    implementation(platform("androidx.compose:compose-bom:2026.06.01"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.material:material")
    implementation("androidx.compose.ui:ui")
    testImplementation("junit:junit:4.13.2")
}
