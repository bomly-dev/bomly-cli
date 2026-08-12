package jvmreach

import (
	"sort"
	"strings"
)

// packagePrefixToArtifacts maps fully-qualified Java/Kotlin/Scala
// package prefixes to one or more Maven artifact coordinates that
// publish into them. The map is hand-curated and covers the most
// commonly-imported third-party libraries on the JVM.
//
// Resolution: each scanned import is matched against the **longest**
// registered prefix that is a prefix of the import (component-wise:
// `com.fasterxml.jackson.databind` is a prefix of
// `com.fasterxml.jackson.databind.ObjectMapper` but not of
// `com.fasterxml.jackson.databindfoo.X`). On a hit, every artifact
// listed for that prefix is added to the imported-artifact set; the
// BFS through Graph.Dependencies then expands the set transitively.
//
// Why a curated map. The Java package -> Maven artifact relationship
// is genuinely arbitrary — there is no naming convention that holds
// across vendors. Unlike Python (where `requests` the module almost
// always lives in `requests` the dist), Java has no fallback. A
// missing prefix produces a false-negative for direct imports; the
// dep-graph BFS recovers it if any correctly-mapped neighbor is
// imported.
//
// Coordinates are stored lowercase, in `group:artifact` form. PRs
// extending the map are welcome.
var packagePrefixToArtifacts = map[string][]string{
	// Jackson — split across many artifacts.
	"com.fasterxml.jackson.core":            {"com.fasterxml.jackson.core:jackson-core"},
	"com.fasterxml.jackson.databind":        {"com.fasterxml.jackson.core:jackson-databind"},
	"com.fasterxml.jackson.annotation":      {"com.fasterxml.jackson.core:jackson-annotations"},
	"com.fasterxml.jackson.datatype.jsr310": {"com.fasterxml.jackson.datatype:jackson-datatype-jsr310"},
	"com.fasterxml.jackson.datatype.jdk8":   {"com.fasterxml.jackson.datatype:jackson-datatype-jdk8"},
	"com.fasterxml.jackson.module.kotlin":   {"com.fasterxml.jackson.module:jackson-module-kotlin"},
	"com.fasterxml.jackson.module.scala":    {"com.fasterxml.jackson.module:jackson-module-scala"},
	"com.fasterxml.jackson.dataformat.yaml": {"com.fasterxml.jackson.dataformat:jackson-dataformat-yaml"},
	"com.fasterxml.jackson.dataformat.xml":  {"com.fasterxml.jackson.dataformat:jackson-dataformat-xml"},

	// Spring Framework + Spring Boot. We keep these coarse; the
	// real artifact split is at sub-package level (e.g. spring-web
	// vs spring-webmvc) and over-attributing to the umbrella has
	// a small false-positive cost vs missing real reachability.
	"org.springframework.boot":               {"org.springframework.boot:spring-boot"},
	"org.springframework.boot.autoconfigure": {"org.springframework.boot:spring-boot-autoconfigure"},
	"org.springframework.boot.actuate":       {"org.springframework.boot:spring-boot-actuator"},
	"org.springframework.web.servlet":        {"org.springframework:spring-webmvc"},
	"org.springframework.web.reactive":       {"org.springframework:spring-webflux"},
	"org.springframework.web":                {"org.springframework:spring-web"},
	"org.springframework.context":            {"org.springframework:spring-context"},
	"org.springframework.beans":              {"org.springframework:spring-beans"},
	"org.springframework.core":               {"org.springframework:spring-core"},
	"org.springframework.data.jpa":           {"org.springframework.data:spring-data-jpa"},
	"org.springframework.data.mongodb":       {"org.springframework.data:spring-data-mongodb"},
	"org.springframework.data.redis":         {"org.springframework.data:spring-data-redis"},
	"org.springframework.security":           {"org.springframework.security:spring-security-core"},
	"org.springframework.kafka":              {"org.springframework.kafka:spring-kafka"},

	// Logging.
	"org.apache.logging.log4j": {"org.apache.logging.log4j:log4j-api", "org.apache.logging.log4j:log4j-core"},
	"org.slf4j":                {"org.slf4j:slf4j-api"},
	"ch.qos.logback":           {"ch.qos.logback:logback-classic", "ch.qos.logback:logback-core"},
	"java.util.logging":        nil, // stdlib, listed for clarity
	"org.apache.log4j":         {"log4j:log4j"},

	// Apache Commons.
	"org.apache.commons.lang3":        {"org.apache.commons:commons-lang3"},
	"org.apache.commons.lang":         {"commons-lang:commons-lang"},
	"org.apache.commons.io":           {"commons-io:commons-io"},
	"org.apache.commons.collections4": {"org.apache.commons:commons-collections4"},
	"org.apache.commons.collections":  {"commons-collections:commons-collections"},
	"org.apache.commons.codec":        {"commons-codec:commons-codec"},
	"org.apache.commons.text":         {"org.apache.commons:commons-text"},
	"org.apache.commons.cli":          {"commons-cli:commons-cli"},
	"org.apache.commons.compress":     {"org.apache.commons:commons-compress"},
	"org.apache.commons.csv":          {"org.apache.commons:commons-csv"},
	"org.apache.commons.math3":        {"org.apache.commons:commons-math3"},
	"org.apache.commons.pool2":        {"org.apache.commons:commons-pool2"},
	"org.apache.commons.dbcp2":        {"org.apache.commons:commons-dbcp2"},
	"org.apache.commons.beanutils":    {"commons-beanutils:commons-beanutils"},
	"org.apache.commons.fileupload":   {"commons-fileupload:commons-fileupload"},
	"org.apache.commons.fileupload2":  {"org.apache.commons:commons-fileupload2-core"},
	"org.apache.xml.security":         {"org.apache.santuario:xmlsec"},
	"org.mindrot.jbcrypt":             {"org.mindrot:jbcrypt"},
	"org.mindrot":                     {"org.mindrot:jbcrypt"},

	// Apache Struts 2.
	"org.apache.struts2":      {"org.apache.struts:struts2-core"},
	"com.opensymphony.xwork2": {"org.apache.struts.xwork:xwork-core"},

	// Keycloak (SAML / common).
	"org.keycloak.adapters": {"org.keycloak:keycloak-saml-core"},
	"org.keycloak":          {"org.keycloak:keycloak-core"},

	// H2 / Kafka / other widely-pinned demos.
	"org.h2":                {"com.h2database:h2"},
	"org.apache.kafka":      {"org.apache.kafka:kafka-clients"},
	"kafka":                 {"org.apache.kafka:kafka_2.12"},
	"net.bull.javamelody":   {"net.bull.javamelody:javamelody-core"},
	"com.orientechnologies": {"com.orientechnologies:orientdb-core"},

	// Apache Sling.
	"org.apache.sling.engine": {"org.apache.sling:org.apache.sling.engine"},

	// Google.
	"com.google.common":     {"com.google.guava:guava"},
	"com.google.gson":       {"com.google.code.gson:gson"},
	"com.google.protobuf":   {"com.google.protobuf:protobuf-java"},
	"com.google.inject":     {"com.google.inject:guice"},
	"com.google.errorprone": {"com.google.errorprone:error_prone_annotations"},
	"io.grpc":               {"io.grpc:grpc-core", "io.grpc:grpc-api"},

	// Testing.
	"org.junit.jupiter":  {"org.junit.jupiter:junit-jupiter-api", "org.junit.jupiter:junit-jupiter-engine"},
	"org.junit.platform": {"org.junit.platform:junit-platform-launcher"},
	"org.junit":          {"junit:junit"},
	"junit.framework":    {"junit:junit"},
	"org.assertj.core":   {"org.assertj:assertj-core"},
	"org.mockito":        {"org.mockito:mockito-core"},
	"org.testng":         {"org.testng:testng"},
	"io.cucumber":        {"io.cucumber:cucumber-java"},
	"org.hamcrest":       {"org.hamcrest:hamcrest"},

	// Networking / HTTP clients.
	"io.netty":              {"io.netty:netty-all"},
	"okhttp3":               {"com.squareup.okhttp3:okhttp"},
	"retrofit2":             {"com.squareup.retrofit2:retrofit"},
	"org.apache.http":       {"org.apache.httpcomponents:httpclient"},
	"org.apache.hc.client5": {"org.apache.httpcomponents.client5:httpclient5"},
	"org.apache.hc.core5":   {"org.apache.httpcomponents.core5:httpcore5"},
	"com.squareup.okio":     {"com.squareup.okio:okio"},

	// Database / persistence.
	"org.hibernate":       {"org.hibernate.orm:hibernate-core"},
	"javax.persistence":   {"javax.persistence:javax.persistence-api"},
	"jakarta.persistence": {"jakarta.persistence:jakarta.persistence-api"},
	"org.postgresql":      {"org.postgresql:postgresql"},
	"com.mysql.cj":        {"com.mysql:mysql-connector-j"},
	"redis.clients.jedis": {"redis.clients:jedis"},
	"com.mongodb":         {"org.mongodb:mongodb-driver-sync"},

	// XML / JSON.
	"org.dom4j":        {"org.dom4j:dom4j"},
	"org.jdom2":        {"org.jdom:jdom2"},
	"javax.xml.bind":   {"jakarta.xml.bind:jakarta.xml.bind-api"},
	"jakarta.xml.bind": {"jakarta.xml.bind:jakarta.xml.bind-api"},

	// Misc widely-used.
	"org.yaml.snakeyaml":   {"org.yaml:snakeyaml"},
	"com.zaxxer.hikari":    {"com.zaxxer:HikariCP"},
	"io.swagger":           {"io.swagger:swagger-annotations"},
	"io.swagger.v3":        {"io.swagger.core.v3:swagger-annotations"},
	"org.eclipse.jetty":    {"org.eclipse.jetty:jetty-server"},
	"org.glassfish.jersey": {"org.glassfish.jersey.core:jersey-server"},
	"javax.servlet":        {"javax.servlet:javax.servlet-api"},
	"jakarta.servlet":      {"jakarta.servlet:jakarta.servlet-api"},
	"io.micrometer":        {"io.micrometer:micrometer-core"},
	"io.opentelemetry":     {"io.opentelemetry:opentelemetry-api"},
	"io.opentracing":       {"io.opentracing:opentracing-api"},

	// Kotlin libraries.
	"kotlinx.coroutines":        {"org.jetbrains.kotlinx:kotlinx-coroutines-core"},
	"kotlinx.serialization":     {"org.jetbrains.kotlinx:kotlinx-serialization-core"},
	"org.jetbrains.annotations": {"org.jetbrains:annotations"},

	// Scala libraries.
	"akka":   {"com.typesafe.akka:akka-actor"},
	"cats":   {"org.typelevel:cats-core"},
	"scalaz": {"org.scalaz:scalaz-core"},
	"play":   {"com.typesafe.play:play"},
	"slick":  {"com.typesafe.slick:slick"},

	// Groovy.
	"groovy": {"org.codehaus.groovy:groovy"},

	// Build / annotation processors that appear in app source occasionally.
	"lombok":             {"org.projectlombok:lombok"},
	"javax.inject":       {"javax.inject:javax.inject"},
	"jakarta.inject":     {"jakarta.inject:jakarta.inject-api"},
	"javax.validation":   {"javax.validation:validation-api"},
	"jakarta.validation": {"jakarta.validation:jakarta.validation-api"},
}

// stdlibPackagePrefixes lists package roots that are part of the JDK,
// Kotlin, Scala, or Groovy standard libraries. Imports under these
// roots are dropped from the import set before mapping.
var stdlibPackagePrefixes = []string{
	"java.",
	"javax.crypto.",
	"javax.naming.",
	"javax.net.",
	"javax.security.",
	"javax.sound.",
	"javax.sql.",
	"javax.swing.",
	"javax.tools.",
	"javax.imageio.",
	"javax.accessibility.",
	"javax.activation.",
	"javax.management.",
	"javax.print.",
	"javax.script.",
	"javax.smartcardio.",
	"javax.transaction.",
	"jdk.",
	"sun.",
	"com.sun.",
	"kotlin.",
	"kotlinx.io.", // some kotlinx parts are stdlib-adjacent
	"scala.",
	"groovy.lang.",
	"groovy.util.",
}

// isStdlibImport reports whether the given full import path lives in
// a stdlib package root.
func isStdlibImport(fqn string) bool {
	for _, prefix := range stdlibPackagePrefixes {
		if strings.HasPrefix(fqn, prefix) {
			return true
		}
	}
	return false
}

// resolveArtifacts returns the set of Maven coordinates that should
// be added to the import set for one scanned import. Empty result
// means: stdlib, unknown prefix, or empty input — caller drops it.
//
// The match is longest-prefix component-wise (so
// `com.fasterxml.jackson.databind.foo` resolves the `databind`
// artifact, not the broader `core`). The lookup never falls through
// to a synthesized coordinate — Java packages and Maven coordinates
// have no usable identity relationship.
func resolveArtifacts(fqn string) []string {
	fqn = strings.TrimSpace(fqn)
	if fqn == "" || isStdlibImport(fqn) {
		return nil
	}
	// Try every component prefix from longest to shortest.
	parts := strings.Split(fqn, ".")
	for i := len(parts); i > 0; i-- {
		candidate := strings.Join(parts[:i], ".")
		if artifacts, ok := packagePrefixToArtifacts[candidate]; ok {
			out := make([]string, 0, len(artifacts))
			for _, a := range artifacts {
				if a == "" {
					continue
				}
				out = append(out, strings.ToLower(a))
			}
			sort.Strings(out)
			return out
		}
	}
	return nil
}

// canonicalCoord normalizes a Maven coordinate to lowercase for
// case-insensitive comparison against the import set.
func canonicalCoord(group, artifact string) string {
	g := strings.ToLower(strings.TrimSpace(group))
	a := strings.ToLower(strings.TrimSpace(artifact))
	if g == "" || a == "" {
		return ""
	}
	return g + ":" + a
}
