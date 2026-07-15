package polyglot.java;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * LicenseParser - Parses and validates license information from multiple formats.
 * Designed for the licenselens tool as a dependency SBOM gate component.
 */
public final class LicenseParser {

    // Thread-safe cache: key = normalized license ID, value = parsed result
    private static final ConcurrentHashMap<String, ParsedLicense> CACHE = new ConcurrentHashMap<>();

    // Common regex patterns for different formats
    private static final Pattern SPDX_PATTERN = Pattern.compile(
        "(SPDX-Ref-Identifier|LicenseID):\\s*(.+)", 
        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
    );

    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[^\\s\"'<>]+", 
        Pattern.CASE_INSENSITIVE
    );

    // Known license identifiers for quick lookup
    private static final Set<String> KNOWN_LICENSE_IDS = new HashSet<>(Arrays.asList(
        "MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0-only", "LGPL-2.1-only",
        "MPL-2.0", "EPL-2.0", "ISC", "CC-BY-4.0", "WTFPL"
    ));

    private LicenseParser() {} // Utility class, prevent instantiation

    /**
     * Main entry point for parsing license content.
     */
    public static ParsedLicense parse(String input) {
        if (input == null || input.isBlank()) {
            return new ParsedLicense(null, "null", null, null, null, true);
        }

        String normalizedId = normalizeLicenseId(input);
        
        // Check cache first
        ParsedLicense cached = CACHE.get(normalizedId);
        if (cached != null) {
            return cached;
        }

        // Parse the input
        ParsedLicense result = parseContent(input);
        
        // Cache the result
        CACHE.putIfAbsent(normalizedId, result);
        return result;
    }

    /**
     * Parses license content from various formats.
     */
    private static ParsedLicense parseContent(String input) {
        String text = input.trim();
        
        // Try SPDX format first (most common in SBOMs)
        if (text.startsWith("SPDX-Ref-Identifier:") || 
            text.startsWith("LicenseID:")) {
            return parseSPDX(text);
        }

        // Try URL-based license reference
        Matcher urlMatcher = URL_PATTERN.matcher(text);
        if (urlMatcher.find()) {
            String url = urlMatcher.group(1).trim();
            ParsedLicense result = new ParsedLicense(null, "URL", url, null, null, false);
            return result;
        }

        // Try plain text license content
        if (text.length() > 50) {
            // Likely actual license text - extract header info
            String[] lines = text.split("\n");
            ParsedLicense result = parsePlainText(lines);
            return result;
        }

        // Fallback: treat as unknown/short reference
        return new ParsedLicense(null, "unknown", null, null, null, true);
    }

    /**
     * Parses SPDX-formatted license data.
     */
    private static ParsedLicense parseSPDX(String text) {
        Matcher matcher = SPDX_PATTERN.matcher(text);
        
        if (matcher.find()) {
            String id = matcher.group(2).trim();
            
            // Normalize the ID for comparison
            String normalized = normalizeLicenseId(id);
            
            // Check against known licenses
            boolean isKnown = KNOWN_LICENSE_IDS.contains(normalized) || 
                             KNOWN_LICENSE_IDS.contains(id.toUpperCase());
            
            return new ParsedLicense(
                isKnown ? normalized : id,
                "SPDX",
                null,
                text,
                isKnown ? "known" : "custom",
                false
            );
        }

        // No SPDX format found - treat as plain reference
        return new ParsedLicense(null, "spdx-fallback", text, null, null, true);
    }

    /**
     * Parses plain text license content.
     */
    private static ParsedLicense parsePlainText(String[] lines) {
        StringBuilder header = new StringBuilder();
        
        // Look for common license headers in the first few lines
        for (int i = 0; i < Math.min(10, lines.length); i++) {
            String line = lines[i].trim().toLowerCase();
            
            if (line.isEmpty()) continue;
            
            header.append(line).append("\n");
            
            // Check for license type indicators
            if (line.contains("mit") || line.contains("apache")) {
                return new ParsedLicense(
                    "MIT", 
                    "detected-header", 
                    null, 
                    lines[0], 
                    "detected", 
                    false
                );
            } else if (line.contains("gpl-3.0") || line.contains("gnu general public")) {
                return new ParsedLicense(
                    "GPL-3.0-only", 
                    "detected-header", 
                    null, 
                    lines[0], 
                    "detected", 
                    false
                );
            } else if (line.contains("bsd") && !line.contains("gnu")) {
                return new ParsedLicense(
                    "BSD-3-Clause", 
                    "detected-header", 
                    null, 
                    lines[0], 
                    "detected", 
                    false
                );
            }
        }

        // If header contains URL, extract it
        Matcher urlMatcher = URL_PATTERN.matcher(header.toString());
        if (urlMatcher.find()) {
            String url = urlMatcher.group(1).trim();
            return new ParsedLicense(null, "URL", url, null, null, false);
        }

        // Otherwise treat as unknown text content
        return new ParsedLicense(null, "text-content", header.toString(), null, null, true);
    }

    /**
     * Normalizes a license identifier for consistent comparison.
     */
    public static String normalizeLicenseId(String input) {
        if (input == null || input.isBlank()) {
            return "null";
        }

        // Convert to uppercase and trim
        String normalized = input.trim().toUpperCase();

        // Remove common prefixes/suffixes for comparison
        String[] cleanParts = new String[]{
            "SPDX-REF-", "LICENSEID:", "LIC:", "LISCEN", 
            "COPYLEFT", "OPEN", "PUBLIC"
        };

        for (String part : cleanParts) {
            if (normalized.contains(part)) {
                normalized = normalized.replace(part, "");
            }
        }

        // Remove trailing punctuation
        normalized = normalized.replaceAll("[^A-Z0-9\\s.-]", "").trim();

        return normalized.isEmpty() ? "unknown" : normalized;
    }

    /**
     * Checks if a license ID is recognized.
     */
    public static boolean isKnownLicense(String id) {
        String normalized = normalizeLicenseId(id);
        return KNOWN_LICENSE_IDS.contains(normalized) || 
               KNOWN_LICENSE_IDS.contains(normalized.toUpperCase());
    }

    /**
     * Parses license from an InputStream (useful for reading files).
     */
    public static ParsedLicense parse(InputStream stream) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder content = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }

            return parse(content.toString());
        }
    }

    /**
     * Parses license from a URI (file or HTTP).
     */
    public static ParsedLicense parse(URI uri) throws IOException, URISyntaxException {
        // Try to read as file first
        try (InputStream stream = java.nio.file.Files.newInputStream(uri)) {
            return parse(stream);
        } catch (java.nio.file.NoSuchFileException e) {
            // Fall back to HTTP/HTTPS
            try (InputStream stream = new java.net.HttpURLConnection(
                    uri.toURL()).getInputStream()) {
                return parse(stream);
            }
        }

        throw new IOException("Could not read from URI: " + uri);
    }

    /**
     * Main demo/test entry point.
     */
    public static void main(String[] args) throws Exception {
        System.out.println("=== LicenseParser Demo ===\n");

        // Test 1: SPDX format
        String spdxInput = "SPDX-Ref-Identifier: MIT";
        ParsedLicense spdxResult = parse(spdxInput);
        printResult("SPDX Input", spdxInput, spdxResult);

        // Test 2: URL reference
        String urlInput = "https://opensource.org/licenses/MIT";
        ParsedLicense urlResult = parse(urlInput);
        printResult("URL Input", urlInput, urlResult);

        // Test 3: Plain text (MIT license header)
        String mitText = """
            MIT License
            
            Copyright (c) 2024 Example Corp.
            
            Permission is hereby granted, free of charge...
            """;
        ParsedLicense mitResult = parse(mitText);
        printResult("Plain Text", mitText.substring(0, 50) + "...", mitResult);

        // Test 4: Unknown license
        String unknownInput = "CustomProprietaryLicense-2024";
        ParsedLicense unknownResult = parse(unknownInput);
        printResult("Unknown License", unknownInput, unknownResult);

        // Test 5: Empty input
        ParsedLicense emptyResult = parse("");
        printResult("Empty Input", "", emptyResult);

        // Test 6: Null input
        ParsedLicense nullResult = parse(null);
        printResult("Null Input", "null", nullResult);

        // Test 7: Cache validation
        System.out.println("\n=== Cache Validation ===");
        String testInput = "SPDX-Ref-Identifier: Apache-2.0";
        ParsedLicense firstParse = parse(testInput);
        ParsedLicense secondParse = parse(testInput);
        
        if (firstParse == secondParse) {
            System.out.println("✓ Cache working: same instance returned");
        } else {
            System.out.println("✗ Cache issue: different instances");
        }

        // Test 8: Normalization
        System.out.println("\n=== Normalization Tests ===");
        String[] testIds = {
            "MIT", 
            "SPDX-REF-MIT", 
            "mit", 
            "  MIT  ",
            "Apache-2.0"
        };

        for (String id : testIds) {
            System.out.printf("Input: %-30s -> Normalized: %s%n", 
                "\"" + id + "\"", 
                normalizeLicenseId(id));
        }

        // Test 9: Known license check
        System.out.println("\n=== Known License Checks ===");
        for (String test : new String[]{"MIT", "GPL-3.0-only", "CustomLicense"}) {
            System.out.printf("Is '%s' known? %s%n", 
                test, isKnownLicense(test));
        }

        // Test 10: Performance benchmark
        System.out.println("\n=== Performance Benchmark ===");
        int iterations = 1000;
        long start = System.nanoTime();
        
        for (int i = 0; i < iterations; i++) {
            parse("SPDX-Ref-Identifier: MIT");
        }

        long elapsed = System.nanoTime() - start;
        double msPerParse = (elapsed / iterations) / 1_000_000.0;
        
        System.out.printf("Parsed %d licenses in %.2f ms%n", 
            iterations, msPerParse);
        System.out.printf("Average: %.4f ms per parse%n", msPerParse);

        // Test 11: InputStream parsing
        System.out.println("\n=== InputStream Parsing ===");
        try (InputStream stream = new java.io.ByteArrayInputStream(
                ("SPDX-Ref-Identifier: BSD-3-Clause".getBytes()))) {
            ParsedLicense streamResult = parse(stream);
            printResult("From Stream", "SPDX-Ref-Identifier: BSD-3-Clause", streamResult);
        }

        System.out.println("\n=== Demo Complete ===");
    }

    /**
     * Helper method to pretty-print a parsed result.
     */
    private static void printResult(String testName, String input, ParsedLicense result) {
        System.out.printf("Test: %s%n", testName);
        System.out.printf("  Input: %s%n", 
            input.length() > 60 ? input.substring(0, 57) + "..." : input);
        System.out.printf("  ID: '%s'%n", result.id());
        System.out.printf("  Type: %s%n", result.type());
        System.out.printf("  URL: %s%n", 
            result.url() != null ? result.url() : "(none)");
        System.out.printf("  Is Known: %s%n", result.isKnown());
        System.out.println();
    }
}

/**
 * Immutable data class representing a parsed license.
 */
class ParsedLicense {
    
    private final String id;
    private final String type;
    private final String url;
    private final String originalText;
    private final String category;
    private final boolean isKnown;

    public ParsedLicense(String id, String type, String url, 
                        String originalText, String category, boolean isKnown) {
        this.id = id;
        this.type = type;
        this.url = url;
        this.originalText = originalText;
        this.category = category;
        this.isKnown = isKnown;
    }

    public String id() { return id; }
    public String type() { return type; }
    public String url() { return url; }
    public String originalText() { return originalText; }
    public String category() { return category; }
    public boolean isKnown() { return isKnown; }

    @Override
    public int hashCode() {
        // Simple hash based on ID and type for cache purposes
        return Objects.hash(id, type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof ParsedLicense)) return false;
        
        ParsedLicense other = (ParsedLicense) obj;
        return id.equals(other.id) && type.equals(other.type);
    }

    @Override
    public String toString() {
        return "ParsedLicense{id='" + id + "', type=" + type + 
               ", url='" + url + "', isKnown=" + isKnown + "}";
    }
}