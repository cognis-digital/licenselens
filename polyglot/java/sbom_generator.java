package polyglot.java;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.spdx.api.model.SpdxDocument;
import org.eclipse.spdx.api.model.SpdxPackage;
import org.eclipse.spdx.api.model.package.SpdxPackageInfo;
import org.eclipse.spdx.api.model.relationship.SpdxRelationshipType;
import org.eclipse.spdx.api.model.spdxitem.SpdxItem;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * SBOM Generator for licenselens.
 * Produces SPDX 2.3 formatted Software Bill of Materials from Maven/Gradle dependencies.
 */
public class sbom_generator {

    private static final String MAVEN_LICENSE_URL = "https://search.maven.org/solrsearch/select?q=g:%22%s%22+AND+a:%22%s%22&rows=1&wt=json";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    public record Dependency(String groupId, String artifactId, String version) {}

    /**
     * Main entry point demonstrating SBOM generation.
     */
    public static void main(String[] args) throws Exception {
        // Example: Generate SBOM for a typical project with 3 dependencies
        List<Dependency> deps = Arrays.asList(
            new Dependency("com.google.guava", "guava", "32.1.0-jre"),
            new Dependency("org.apache.commons", "commons-lang3", "3.14.0"),
            new Dependency("io.jsonwebtoken", "jjwt-api", "0.11.5")
        );

        SBOMBuilder builder = new SBOMBuilder();
        SpdxDocument document = builder.build(deps);

        // Output to stdout as pretty-printed JSON
        String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(document);
        System.out.println("=== SPDX 2.3 SBOM ===");
        System.out.println(json);
    }

    /**
     * Builder that constructs a valid SPDX 2.3 document from dependencies.
     */
    public static class SBOMBuilder {

        private final SpdxDocument.Builder docBuilder = SpdxDocument.builder();

        public SpdxDocument build(List<Dependency> directDeps) throws IOException {
            // Set document metadata
            String documentName = "licenselens-" + System.currentTimeMillis() + "-sbom";
            Instant now = Instant.now();

            docBuilder.setName(documentName);
            docBuilder.setVersion("1.0");
            docBuilder.setDocumentNamespace(URI.create("https://licenselens.example/ns/" + documentName));
            docBuilder.setCreated(now);
            docBuilder.setCreator(new SpdxItem.Builder()
                    .setName("Tool: licenselens")
                    .setVersion("1.0.0")
                    .build());

            // Add direct dependencies as packages with NOASSERTION license (will be resolved)
            Set<String> seen = new HashSet<>();
            for (Dependency dep : directDeps) {
                String key = dep.groupId() + ":" + dep.artifactId() + ":" + dep.version();
                if (!seen.contains(key)) {
                    seen.add(key);
                    addPackage(dep, now);
                }
            }

            // Add relationship: DOCUMENTDESCRIBES (direct deps) and DEPENDS_ON (transitive)
            for (SpdxItem item : docBuilder.getSpdxItems()) {
                if (item instanceof SpdxPackage pkg && !pkg.getName().equals(documentName)) {
                    docBuilder.addRelationship(
                        new SpdxRelationship.Builder()
                            .setRelationshipType(SpdxRelationshipType.DOCUMENTDESCRIBES)
                            .setItemInRelationship(item)
                            .setItemReferenced(docBuilder.getSpdxItems().getFirst())
                            .build()
                    );

                    // Self-reference for DEPENDS_ON (simplified - real impl would track transitive deps)
                    docBuilder.addRelationship(
                        new SpdxRelationship.Builder()
                            .setRelationshipType(SpdxRelationshipType.DEPENDS_ON)
                            .setItemInRelationship(docBuilder.getSpdxItems().getFirst())
                            .setItemReferenced(item)
                            .build()
                    );
                }
            }

            return docBuilder.build();
        }

        private void addPackage(Dependency dep, Instant now) {
            String pkgName = dep.artifactId();
            
            SpdxPackage.Builder pkgBuilder = SpdxPackage.builder()
                .setName(pkgName)
                .setVersion(dep.version())
                .setDownloadLocation("https://search.maven.org/solrsearch/select?q=g:" + 
                    dep.groupId() + "+AND+a:" + dep.artifactId() + "&rows=1&wt=json")
                .setSourceInfo("Maven Central: " + dep.groupId() + ":" + dep.artifactId())
                .setFilesAnalyzed(false)
                .setExternalRefs(
                    new SpdxItem.Builder()
                        .setName("maven-central")
                        .setVersion(dep.version())
                        .build()
                );

            // Try to resolve license from Maven Central
            String resolvedLicense = resolveMavenLicense(dep.groupId(), dep.artifactId());
            
            if (resolvedLicense != null && !resolvedLicense.equals("NOASSERTION")) {
                pkgBuilder.setLicenseConcluded(resolvedLicense);
                pkgBuilder.setLicenseInfoInPackage(
                    new SpdxItem.Builder()
                        .setName(resolvedLicense)
                        .setVersion("")
                        .build()
                );
            }

            docBuilder.addSpdxItem(pkgBuilder.build());
        }

        /**
         * Fetches license from Maven Central API. Returns null if not found or on error.
         */
        private String resolveMavenLicense(String groupId, String artifactId) {
            try {
                String url = MAVEN_LICENSE_URL.formatted(groupId.replace(".", "%2E"), 
                    artifactId.replace(".", "%2E"));
                
                var response = HTTP_CLIENT.send(
                    HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .GET()
                        .build(),
                    HttpResponse.BodyHandlers.ofString()
                );

                if (response.statusCode() == 200) {
                    String body = response.body();
                    var jsonNode = MAPPER.readTree(body);
                    
                    // Parse the Solr search result for license info
                    String licenseId = extractLicenseFromSolr(jsonNode);
                    return licenseId != null ? "NOASSERTION" : null;
                }
            } catch (Exception e) {
                // Network errors are non-fatal - log and continue
            }

            return null;
        }

        /**
         * Extracts license ID from Maven Central Solr response.
         */
        private String extractLicenseFromSolr(com.fasterxml.jackson.databind.JsonNode node) {
            try {
                // Navigate: facet -> facets -> licenses -> licenseId
                if (node.has("facet") && 
                    node.get("facet").has("facets") && 
                    node.get("facet").get("facets").has("licenses")) {

                    var licensesNode = node.get("facet").get("facets").get("licenses");
                    
                    // Get the first license ID (most common)
                    if (licensesNode.isArray() && !licensesNode.isEmpty()) {
                        var firstLicense = licensesNode.get(0);
                        if (firstLicense.has("licenseId")) {
                            return firstLicense.get("licenseId").asText();
                        }
                    }
                }
            } catch (Exception e) {
                // Malformed response - ignore
            }

            return null;
        }
    }
}