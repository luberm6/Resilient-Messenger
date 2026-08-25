plugins {
    kotlin("jvm") version "2.4.10"
    application
}

dependencies {
    implementation("net.java.dev.jna:jna:5.17.0")
}

kotlin { jvmToolchain(17) }
application { mainClass.set("org.resilient.bindings.MainKt") }
