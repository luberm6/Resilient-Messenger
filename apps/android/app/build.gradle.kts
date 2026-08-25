plugins { id("com.android.application") }

android {
    namespace = "org.resilient.messenger"
    compileSdk = 37
    defaultConfig {
        applicationId = "org.resilient.messenger"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures { compose = true }
    buildTypes { release { isMinifyEnabled = true } }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.08.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.material:material")
    implementation("androidx.compose.ui:ui")
    testImplementation("junit:junit:4.13.2")
}
