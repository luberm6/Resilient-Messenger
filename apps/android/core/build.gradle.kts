plugins { id("com.android.library") }

android {
    namespace = "org.resilient.messenger.core"
    compileSdk = 36
    defaultConfig { minSdk = 26 }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.19.1@aar")
}
