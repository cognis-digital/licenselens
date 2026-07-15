/*
 * polyglot/c/sbom_generator.c
 * 
 * LicenLens SBOM Generator - Complete implementation
 * Generates Software Bill of Materials from dependency trees
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#define MAX_PATH 4096
#define MAX_LINE 8192
#define MAX_PACKAGES 10000
#define MAX_DEPS_PER_PKG 500
#define MAX_LICENSE_LEN 256
#define DEFAULT_OUTPUT "sbom.json"

/* Forward declarations */
typedef struct Package Package;
typedef struct SBOM SBOM;

struct Package {
    char name[256];
    char version[128];
    char license[MAX_LICENSE_LEN];
    char source[MAX_PATH];
    char checksum[64];
    int depth;
    bool visited;
};

struct SBOM {
    Package packages[MAX_PACKAGES];
    int package_count;
    char tool_name[64];
    char version[32];
    time_t generated_at;
};

/* Global state */
static SBOM g_sbom = {0};
static const char *g_tool_version = "1.0.0";

/* Utility: Trim whitespace from string in-place */
static void trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return;
    
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}

/* Utility: Check if string is empty after trim */
static bool is_empty(const char *s) {
    const char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    return !*p;
}

/* Parse a package line from input format */
static int parse_package_line(const char *line, Package *pkg) {
    trim(line);
    
    if (!line[0]) return 0;
    
    /* Format: name|version|license|source|checksum */
    const char *sep = strchr(line, '|');
    if (!sep) sep = strchr(line, ' ');
    if (!sep) {
        strncpy(pkg->name, line, sizeof(pkg->name) - 1);
        pkg->name[sizeof(pkg->name) - 1] = '\0';
        return 0;
    }
    
    size_t name_len = sep - line;
    strncpy(pkg->name, line, name_len);
    pkg->name[name_len] = '\0';
    
    /* Find next separator */
    sep++;
    while (*sep && isspace((unsigned char)*sep)) sep++;
    
    const char *ver_sep = strchr(sep, '|');
    if (ver_sep) {
        size_t ver_len = ver_sep - sep;
        strncpy(pkg->version, sep, ver_len);
        pkg->version[ver_len] = '\0';
        
        sep = ver_sep + 1;
        while (*sep && isspace((unsigned char)*sep)) sep++;
        
        const char *lic_sep = strchr(sep, '|');
        if (lic_sep) {
            size_t lic_len = lic_sep - sep;
            strncpy(pkg->license, sep, lic_len);
            pkg->license[lic_len] = '\0';
            
            sep = lic_sep + 1;
            while (*sep && isspace((unsigned char)*sep)) sep++;
            
            const char *src_sep = strchr(sep, '|');
            if (src_sep) {
                size_t src_len = src_sep - sep;
                strncpy(pkg->source, sep, src_len);
                pkg->source[src_len] = '\0';
                
                sep = src_sep + 1;
                while (*sep && isspace((unsigned char)*sep)) sep++;
                
                const char *chk_sep = strchr(sep, '|');
                if (chk_sep) {
                    size_t chk_len = chk_sep - sep;
                    strncpy(pkg->checksum, sep, chk_len);
                    pkg->checksum[chk_len] = '\0';
                } else {
                    strcpy(pkg->checksum, "unknown");
                }
            } else {
                strcpy(pkg->source, "");
                strcpy(pkg->checksum, "unknown");
            }
        } else {
            strcpy(pkg->license, "unknown");
            strcpy(pkg->source, "");
            strcpy(pkg->checksum, "unknown");
        }
    } else {
        strcpy(pkg->version, "latest");
        strcpy(pkg->license, "unknown");
        strcpy(pkg->source, "");
        strcpy(pkg->checksum, "unknown");
    }
    
    return 1;
}

/* Parse a dependency file */
static int parse_dependency_file(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "Warning: Could not open %s: %s\n", filepath, strerror(errno));
        return 0;
    }
    
    Package *pkg_ptr = &g_sbom.packages[g_sbom.package_count];
    char line[MAX_LINE];
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (!found) {
            /* First non-empty line is the package */
            if (parse_package_line(line, pkg_ptr)) {
                g_sbom.packages[g_sbom.package_count].depth = 0;
                found = 1;
            } else {
                continue;
            }
        }
        
        /* Subsequent lines are dependencies */
        if (found) {
            Package *parent = &g_sbom.packages[g_sbom.package_count - 1];
            parent->depth++;
            
            int dep_found = parse_package_line(line, pkg_ptr);
            if (dep_found) {
                g_sbom.packages[g_sbom.package_count].depth = parent->depth;
                g_sbom.package_count++;
            } else {
                /* Empty line or comment */
                if (!is_empty(line)) {
                    fprintf(stderr, "Warning: Malformed dependency at %s\n", filepath);
                }
            }
        }
    }
    
    fclose(fp);
    return g_sbom.package_count > 0 ? 1 : 0;
}

/* Parse a directory for dependency files */
static int parse_directory(const char *dirpath) {
    DIR *dp = opendir(dirpath);
    if (!dp) {
        fprintf(stderr, "Warning: Could not open directory %s: %s\n", dirpath, strerror(errno));
        return 0;
    }
    
    struct dirent *entry;
    int found_any = 0;
    
    while ((entry = readdir(dp)) != NULL) {
        if (!entry->d_name[0]) continue;
        
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
            /* Check for common dependency file patterns */
            const char *patterns[] = {"requirements.txt", "package.json", 
                                      "pom.xml", "Cargo.toml", "go.mod",
                                      "Gemfile.lock", "Pipfile.lock"};
            
            int i = 0;
            while (patterns[i]) {
                if (strstr(entry->d_name, patterns[i])) {
                    found_any = parse_dependency_file(full_path);
                    break;
                }
                i++;
            }
        }
    }
    
    closedir(dp);
    return found_any;
}

/* Parse a single file path */
static int parse_single_file(const char *filepath) {
    /* Check if it's a directory or file */
    struct stat st;
    if (stat(filepath, &st) == 0 && S_ISDIR(st.st_mode)) {
        return parse_directory(filepath);
    } else {
        return parse_dependency_file(filepath);
    }
}

/* Escape string for JSON output */
static void json_escape(const char *src, char *dest, size_t dest_size) {
    size_t i = 0, j = 0;
    
    while (src[i] && j < dest_size - 1) {
        if (src[i] == '\\' || src[i] == '"') {
            if (j + 2 < dest_size) {
                dest[j++] = '\\';
                dest[j++] = src[i];
            }
        } else if (src[i] == '\n' || src[i] == '\r' || src[i] == '\t') {
            if (j + 1 < dest_size) {
                dest[j++] = '\\';
                dest[j++] = 'n';
            }
        } else {
            dest[j++] = src[i];
        }
        i++;
    }
    
    dest[j] = '\0';
}

/* JSON output helper */
static void json_string(const char *key, const char *value) {
    printf("\"%s\":", key);
    char escaped[MAX_LINE];
    json_escape(value, escaped, sizeof(escaped));
    printf("\"%s\"", escaped);
}

/* Generate SBOM JSON output */
static int generate_json_output(const char *output_path) {
    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not create output file %s\n", output_path);
        return -1;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    
    /* SPDX 2.3 format */
    fprintf(fp, "{\n");
    json_string("spdxVersion", "SPDX-2.3");
    printf(",\n");
    json_string("dataVersion", "1.0");
    printf(",\n");
    json_string("name", g_sbom.tool_name);
    printf(",\n");
    json_string("documentNamespace", "https://licenselens.org/sbom/");
    printf(",\n");
    json_string("SPDXID", "SPDXRef-DOCUMENT");
    printf(",\n");
    json_string("created", timestamp);
    printf(",\n");
    json_string("creators", "Tool: LicenLens/" g_sbom.version);
    printf(",\n");
    
    /* Packages */
    fprintf(fp, "  \"packages\": [\n");
    
    for (int i = 0; i < g_sbom.package_count; i++) {
        Package *pkg = &g_sbom.packages[i];
        
        if (i > 0) printf(",\n");
        printf("    {\n");
        json_string("SPDXID", "SPDXRef-Package-" pkg->name);
        printf(",\n");
        json_string("name", pkg->name);
        printf(",\n");
        json_string("versionInfo", pkg->version);
        printf(",\n");
        json_string("downloadLocation", "https://licenselens.org/resolve/" pkg->name);
        printf(",\n");
        json_string("filesAnalyzed", "true");
        printf(",\n");
        json_string("licenseConcluded", pkg->license ? pkg->license : "NOASSERTION");
        printf(",\n");
        json_string("copyrightText", "Copyright (c) 2024 LicenLens Contributors");
        printf("\n    }");
    }
    
    fprintf(fp, "\n  ]\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    return 0;
}

/* Generate CycloneDX JSON output */
static int generate_cyclonedx_output(const char *output_path) {
    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not create output file %s\n", output_path);
        return -1;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    
    fprintf(fp, "{\n");
    json_string("bomFormat", "CycloneDX");
    printf(",\n");
    json_string("specVersion", "1.5");
    printf(",\n");
    json_string("version", "1");
    printf(",\n");
    json_string("metadata", "{");
    json_string("timestamp", timestamp);
    printf(", ");
    json_string("tools", "[{");
    json_string("name", "LicenLens");
    printf(", ");
    json_string("version", g_sbom.version);
    printf("}]");
    printf("}");
    printf(",\n");
    
    /* Components */
    fprintf(fp, "  \"components\": [\n");
    
    for (int i = 0; i < g_sbom.package_count; i++) {
        Package *pkg = &g_sbom.packages[i];
        
        if (i > 0) printf(",\n");
        printf("    {\n");
        json_string("name", pkg->name);
        printf(",\n");
        json_string("version", pkg->version);
        printf(",\n");
        json_string("type", "library");
        printf(",\n");
        json_string("scope", "required");
        printf(",\n");
        json_string("licenses", "[{");
        json_string("name", pkg->license ? pkg->license : "NOASSERTION");
        printf("}]");
        printf("\n    }");
    }
    
    fprintf(fp, "\n  ]\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    return 0;
}

/* Generate SPDX text output */
static int generate_spdx_text_output(const char *output_path) {
    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not create output file %s\n", output_path);
        return -1;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    
    fprintf(fp, "# SPDX-FileCopyrightText: 2024 LicenLens Contributors\n");
    fprintf(fp, "# SPDX-License-Identifier: MIT\n");
    fprintf(fp, "# Generated by LicenLens %s\n", g_sbom.version);
    fprintf(fp, "#\n");
    
    for (int i = 0; i < g_sbom.package_count; i++) {
        Package *pkg = &g_sbom.packages[i];
        
        fprintf(fp, "## Package: %s@%s\n", pkg->name, pkg->version);
        fprintf(fp, "# SPDX-FileCopyrightText: 2024 LicenLens Contributors\n");
        fprintf(fp, "# SPDX-License-Identifier: %s\n", 
                pkg->license ? pkg->license : "NOASSERTION");
        fprintf(fp, "#\n");
    }
    
    fclose(fp);
    return 0;
}

/* Print summary to stderr */
static void print_summary(void) {
    printf("SBOM Generator Summary\n");
    printf("======================\n");
    printf("Packages found: %d\n", g_sbom.package_count);
    printf("Tool: LicenLens %s\n", g_sbom.version);
    printf("Generated at: %s\n", ctime(&g_sbom.generated_at));
}

/* Parse command line arguments */
static int parse_args(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [options] <input> [<output>]\n", argv[0]);
        fprintf(stderr, "\nOptions:\n");
        fprintf(stderr, "  -f, --format FORMAT   Output format: json|cyclonedx|spdx-text\n");
        fprintf(stderr, "                        Default: json\n");
        fprintf(stderr, "  -d, --directory DIR   Input directory (recursive)\n");
        fprintf(stderr, "  -o, --output FILE     Output file path\n");
        fprintf(stderr, "  -h, --help            Show this help message\n");
        return 1;
    }
    
    int opt_format = 0;
    const char *input_path = NULL;
    const char *output_path = DEFAULT_OUTPUT;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--format") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -f requires an argument