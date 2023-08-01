import com.android.build.gradle.api.LibraryVariant

/*
 * Copyright (c) 2012-2016 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

plugins {
    id("com.android.library")
    id("checkstyle")

    id("kotlin-android")
    id("maven-publish")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = "com.github.eastsss"
            artifactId = "openvpn_library"
            version = "1.0"

            afterEvaluate {
                from(components["release"])
            }
        }
    }
}

android {
    namespace = "de.blinkt.openvpn"
    compileSdk = 33

    // Also update runcoverity.sh
    ndkVersion = "25.1.8937393"

    defaultConfig {
        aarMetadata {
            minCompileSdk = 21
        }
        minSdk = 21
        targetSdk = 33
        externalNativeBuild {
            cmake {
            }
        }
    }

    testOptions.unitTests.isIncludeAndroidResources = true

    externalNativeBuild {
        cmake {
            path = File("${projectDir}/src/main/cpp/CMakeLists.txt")
        }
    }

    sourceSets {
        getByName("main") {
            aidl.srcDir("src/main/aidl")
        }

        getByName("debug") {
        }

        getByName("release") {
        }
    }

    lint {
        enable += setOf(
            "BackButton",
            "EasterEgg",
            "StopShip",
            "IconExpectedSize",
            "GradleDynamicVersion",
            "NewerVersionAvailable"
        )
        checkOnly += setOf("ImpliedQuantity", "MissingQuantity")
        disable += setOf("MissingTranslation", "UnsafeNativeCodeLocation")
    }

    compileOptions {
        targetCompatibility = JavaVersion.VERSION_1_8
        sourceCompatibility = JavaVersion.VERSION_1_8
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("x86", "x86_64", "armeabi-v7a", "arm64-v8a")
            isUniversalApk = true
        }
    }

    buildFeatures {
        aidl = true
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

var swigcmd = "swig"
// Workaround for macOS(arm64) and macOS(intel) since it otherwise does not find swig and
// I cannot get the Exec task to respect the PATH environment :(
if (file("/opt/homebrew/bin/swig").exists())
    swigcmd = "/opt/homebrew/bin/swig"
else if (file("/usr/local/bin/swig").exists())
    swigcmd = "/usr/local/bin/swig"


fun registerGenTask(variantName: String, variantDirName: String): File {
    val baseDir = File(buildDir, "generated/source/ovpn3swig/${variantDirName}")
    val genDir = File(baseDir, "net/openvpn/ovpn3")

    tasks.register<Exec>("generateOpenVPN3Swig${variantName}")
    {

        doFirst {
            mkdir(genDir)
        }
        commandLine(
            listOf(
                swigcmd,
                "-outdir",
                genDir,
                "-outcurrentdir",
                "-c++",
                "-java",
                "-package",
                "net.openvpn.ovpn3",
                "-Isrc/main/cpp/openvpn3/client",
                "-Isrc/main/cpp/openvpn3/",
                "-DOPENVPN_PLATFORM_ANDROID",
                "-o",
                "${genDir}/ovpncli_wrap.cxx",
                "-oh",
                "${genDir}/ovpncli_wrap.h",
                "src/main/cpp/openvpn3/client/ovpncli.i"
            )
        )
        inputs.files("src/main/cpp/openvpn3/client/ovpncli.i")
        outputs.dir(genDir)

    }
    return baseDir
}

android.libraryVariants.all {
    val sourceDir = registerGenTask(name, baseName.replace("-", "/"))
    val task = tasks.named("generateOpenVPN3Swig${name}").get()

    registerJavaGeneratingTask(task, sourceDir)
}

dependencies {
    implementation("androidx.annotation:annotation:1.3.0")
    implementation("androidx.core:core:1.9.0")
    implementation("androidx.localbroadcastmanager:localbroadcastmanager:1.1.0")
}