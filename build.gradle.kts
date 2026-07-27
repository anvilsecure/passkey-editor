plugins {
    id("java")
}

// The single source of truth for the extension version. It is filtered into
// src/main/resources/passkey-editor.properties below and read back at runtime, so the About tab and the
// prefilled issue links always report the version this jar was actually built from.
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Provided by Burp at runtime - MUST stay compileOnly (bundling causes classloader conflicts → silent tab failures).
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")

    // CBOR/COSE codec. Pinned to a version proven for malformed-structure construction (latest is 0.31.7; bump after the
    // byte-identity tests pass). Pulls webauthn4j-util + Jackson (databind + core + annotations +
    // dataformat-cbor) + slf4j-api transitively (verified via runtimeClasspath; no kerby-asn1 in 0.28.3-core).
    implementation("com.webauthn4j:webauthn4j-core:0.28.3.RELEASE")
    implementation("com.google.code.gson:gson:2.14.0")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // Montoya on the TEST classpath only (interfaces + enums) so JUnit can construct a reflect.Proxy
    // MontoyaApi double and call PasskeyAutoHandler.compute() headlessly (the dual-seam inert no-op proof).
    // It is NOT bundled into the fat jar: the jar task bundles `runtimeClasspath` (implementation deps),
    // which `testImplementation` never feeds - so the compileOnly classloader-conflict guard is preserved.
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.4")
}

// Burp supports Java 21 or lower. `options.release`, NOT sourceCompatibility/targetCompatibility:
// the latter pair sets the bytecode version but still compiles against the CURRENT JDK's class
// library, so building on a newer JDK links post-21 APIs that only fail at runtime, inside Burp.
// `release` pins the API surface too, so the build breaks at compile time instead.
tasks.withType<JavaCompile> {
    options.release.set(21)
    options.encoding = "UTF-8"
}

// Stamp the project version into the one resource the extension reads it back from. Scoped to that
// single file so no other resource is run through Groovy templating.
tasks.processResources {
    val extensionVersion = project.version.toString()
    inputs.property("extensionVersion", extensionVersion)
    filesMatching("passkey-editor.properties") {
        expand(mapOf("version" to extensionVersion))
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// Fat jar: bundle runtime deps (webauthn4j + transitive Jackson, gson) into the extension jar (starter's mechanism).
// Switch to the Shadow plugin with mergeServiceFiles() ONLY if a runtime ServiceLoader / duplicate-resource error appears.
tasks.jar {
    // Keep the artifact at build/libs/passkey-editor.jar. Declaring a project version would otherwise
    // append it to the file name, changing the path reloaded in Burp on every release.
    archiveVersion.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    // The MIT terms require the copyright and permission notice to travel with every copy, and the jar
    // is what ships. Both files are bundled under names of their own so they cannot collide with the
    // META-INF/LICENSE entries the third-party jars bring in (duplicatesStrategy = EXCLUDE keeps only
    // the first file seen at a path, so a collision would silently drop one of them).
    from("LICENSE") { into("META-INF"); rename { "LICENSE-passkey-editor.txt" } }
    from("THIRD-PARTY-NOTICES.md") { into("META-INF") }

    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}
