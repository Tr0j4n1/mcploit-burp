import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.0.21"
    // Maintained fork. johnrengelman's 8.1.1 breaks on Gradle 8.9 and later.
    id("com.gradleup.shadow") version "8.3.5"
}

group = "io.mcploit"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    // Provided by Burp at runtime. Bump to match your Burp build if this fails
    // to resolve; Help > About shows the version.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2023.12.1")

    // Shaded into the jar. Burp exposes no JSON parser to extensions.
    implementation("com.google.code.gson:gson:2.11.0")
}

// No jvmToolchain here on purpose. Toolchain resolution would demand a JDK 17
// install or the foojay resolver plugin; this just compiles with whatever JDK
// runs Gradle and emits 17 bytecode. Both targets must agree or Gradle fails
// the build on inconsistent JVM-target compatibility.
kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.shadowJar {
    archiveBaseName.set("mcploit-burp")
    archiveClassifier.set("")
    archiveVersion.set("")
    relocate("com.google.gson", "io.mcploit.burp.shaded.gson")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
