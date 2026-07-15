/*
 * polyglot/c/license_parser.c
 * 
 * License Parser for licenselens - Dependency license + SBOM gate
 * 
 * Parses SPDX expressions, text files, and metadata to identify
 * software licenses with canonicalization and validation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

/* ============================================================================
 * Configuration
 */

#define MAX_LICENSE_DB_ENTRIES 2048
#define MAX_TEXT_SIZE 65536
#define MAX_SPDX_EXPR_LEN 1024
#define MIN_CONFIDENCE_SCORE 0.7f

/* ============================================================================
 * Data Structures
 */

typedef struct {
    const char *spdx_id;
    const char *short_name;
    const char *full_name;
    const char *url;
    float confidence_threshold;
} LicenseEntry;

typedef enum {
    LICENSE_UNKNOWN,
    LICENSE_PERMISSIVE,
    LICENSE_COPYLEFT,
    LICENSE_RESTRICTED,
    LICENSE_MIXED,
    LICENSE_INVALID
} LicenseType;

typedef struct {
    const char *source;           /* "spdx", "text_file", "metadata" */
    const char *raw_content;      /* Original input */
    int content_len;              /* Length of raw content */
    const char *detected_id;      /* Canonical SPDX ID if found */
    LicenseType type;             /* Type classification */
    float confidence;             /* Detection confidence (0.0 - 1.0) */
    const char *notes;            /* Additional notes or warnings */
} ParseResult;

/* ============================================================================
 * License Database (Common Open Source Licenses)
 */

static LicenseEntry license_db[] = {
    /* Permissive licenses */
    {"MIT", "MIT", "MIT License", 
     "https://opensource.org/licenses/MIT", 0.95f},
    
    {"Apache-2.0", "APACHE-2.0", "Apache License 2.0",
     "https://www.apache.org/licenses/LICENSE-2.0", 0.98f},
     
    {"BSD-3-Clause", "BSD-3CLAUSE", "BSD 3-Clause License",
     "https://opensource.org/licenses/BSD-3-Clause", 0.95f},
    
    {"BSD-2-Clause", "BSD-2CLAUSE", "BSD 2-Clause License",
     "https://opensource.org/licenses/BSD-2-Clause", 0.95f},
     
    {"ISC", "ISC", "ISC License",
     "https://opensource.org/licenses/ISC", 0.94f},
    
    /* Copyleft licenses */
    {"GPL-3.0-only", "GPL-3.0", "GNU General Public License v3.0 only",
     "https://www.gnu.org/licenses/gpl-3.0.html", 0.98f},
     
    {"GPL-3.0-or-later", "GPL-3.0-LATER", 
     "GNU General Public License v3.0 or later",
     "https://www.gnu.org/licenses/gpl-3.0.html", 0.97f},
    
    {"GPL-2.0-only", "GPL-2.0", "GNU General Public License v2.0 only",
     "https://www.gnu.org/licenses/gpl-2.0.html", 0.98f},
     
    {"LGPL-3.0-or-later", "LGPL-3.0-LATER", 
     "Lesser General Public License v3.0 or later",
     "https://www.gnu.org/licenses/lgpl-3.0.html", 0.96f},
    
    /* Other notable licenses */
    {"MPL-2.0", "MPL-2.0", "Mozilla Public License 2.0",
     "https://opensource.org/licenses/MPL-2.0", 0.95f},
     
    {"EPL-2.0", "EPL-2.0", "Eclipse Public License 2.0",
     "https://www.eclipse.org/legal/epl-2.0", 0.94f},
    
    {"CC-BY-4.0", "CC-BY-4.0", "Creative Commons Attribution 4.0",
     "https://creativecommons.org/licenses/by/4.0", 0.93f},
     
    {"Zlib", "ZLIB", "zlib/libpng License",
     "https://opensource.org/licenses/Zlib", 0.92f},
    
    /* Unknown/mixed */
    {NULL, NULL, NULL, NULL, 0.0f}
};

/* ============================================================================
 * Utility Functions
 */

static inline void trim_whitespace(char *str) {
    char *start = str;
    char *end;
    
    while (isspace((unsigned char)*start)) start++;
    
    if (*start == 0) {
        *str = 0;
        return;
    }
    
    end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    
    *(end + 1) = 0;
    memmove(str, start, end - start + 2);
}

static inline int strcasecmp_n(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2))
            return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
        s1++;
        s2++;
    }
    return 0;
}

/* ============================================================================
 * License Detection Functions
 */

static int detect_license_from_text(const char *text, ParseResult *result) {
    const char *upper = text;
    size_t len = strlen(text);
    
    /* Normalize: convert to uppercase for matching */
    while (*upper) {
        *upper++ = toupper((unsigned char)*text);
        text++;
    }
    
    int max_score = 0;
    const char *best_match = NULL;
    
    /* Check against known licenses with fuzzy matching */
    for (int i = 0; license_db[i].spdx_id != NULL; i++) {
        LicenseEntry *entry = &license_db[i];
        
        if (strcasecmp_n(entry->short_name, text) == 0 ||
            strcasecmp_n(entry->full_name, text) == 0 ||
            strcasecmp_n(entry->spdx_id, text) == 0) {
            
            /* Found exact match */
            best_match = entry->spdx_id;
            max_score = (int)(entry->confidence_threshold * 100);
            break;
        }
        
        /* Fuzzy substring check for common patterns */
        if (strstr(text, entry->short_name) != NULL ||
            strstr(text, entry->full_name) != NULL) {
            
            int score = (int)(entry->confidence_threshold * 100);
            if (score > max_score) {
                max_score = score;
                best_match = entry->spdx_id;
            }
        }
    }
    
    /* Check for common license patterns in text */
    const char *patterns[] = {
        "permission to use, copy",           /* MIT-style header */
        "redistribute, modify",              /* Apache-style */
        "make available under the terms of", /* GPL-style */
        "provided that you also make available", /* LGPL/modified GPL */
        "subject to the conditions set forth below", /* BSD-style */
        NULL
    };
    
    if (best_match == NULL) {
        for (int i = 0; patterns[i] != NULL; i++) {
            if (strstr(text, patterns[i]) != NULL) {
                max_score = 60;
                best_match = "MIT-like";
                break;
            }
        }
    }
    
    /* Check for copyleft indicators */
    const char *copyleft_patterns[] = {
        "gnu general public license",
        "lessor general public license", 
        "affero general public license",
        "common development and distribution license (cddl)",
        NULL
    };
    
    if (best_match == NULL) {
        for (int i = 0; copyleft_patterns[i] != NULL; i++) {
            if (strstr(text, copyleft_patterns[i]) != NULL) {
                max_score = 75;
                best_match = "GPL-family";
                break;
            }
        }
    }
    
    /* Default to unknown if no match found */
    if (best_match == NULL || max_score < MIN_CONFIDENCE_SCORE * 100) {
        result->detected_id = "UNKNOWN";
        result->type = LICENSE_UNKNOWN;
        result->confidence = 0.3f;
        snprintf(result->notes, MAX_TEXT_SIZE, 
                 "No clear license match found in text");
    } else if (max_score >= 95) {
        result->detected_id = best_match;
        for (int i = 0; license_db[i].spdx_id != NULL; i++) {
            if (strcasecmp_n(license_db[i].spdx_id, best_match) == 0) {
                result->type = LICENSE_PERMISSIVE;
                result->confidence = license_db[i].confidence_threshold;
                break;
            }
        }
    } else if (max_score >= 85) {
        result->detected_id = best_match;
        for (int i = 0; license_db[i].spdx_id != NULL; i++) {
            if (strcasecmp_n(license_db[i].spdx_id, best_match) == 0) {
                result->type = LICENSE_COPYLEFT;
                result->confidence = license_db[i].confidence_threshold;
                break;
            }
        }
    } else {
        result->detected_id = "PROBABLY-" best_match;
        result->type = LICENSE_UNKNOWN;
        result->confidence = 0.5f + (max_score / 200.0f);
    }
    
    return max_score > 0 ? 1 : 0;
}

/* ============================================================================
 * SPDX Expression Parser
 */

typedef struct {
    const char *expr;
    int pos;
    int length;
} SpdxParserState;

static inline void skip_whitespace(SpdxParserState *s) {
    while (s->pos < s->length && isspace((unsigned char)s->expr[s->pos])) {
        s->pos++;
    }
}

static const char* parse_spdx_id(SpdxParserState *s, char *out, int max_len) {
    skip_whitespace(s);
    
    if (s->pos >= s->length || !isalnum((unsigned char)s->expr[s->pos])) {
        return NULL;
    }
    
    const char *start = &s->expr[s->pos];
    while (s->pos < s->length && 
           isalnum((unsigned char)s->expr[s->pos]) ||
           s->expr[s->pos] == '-' || s->expr[s->pos] == '.' ||
           s->expr[s->pos] == '+' || s->expr[s->pos] == '~') {
        s->pos++;
    }
    
    int len = (int)(s->pos - start);
    if (len > 0 && len < max_len) {
        strncpy(out, start, len);
        out[len] = '\0';
    }
    
    return out;
}

static inline bool parse_spdx_expr(const char *expr, ParseResult *result) {
    SpdxParserState s = { .expr = expr, .pos = 0, .length = (int)strlen(expr) };
    int id_count = 0;
    
    /* Skip leading whitespace */
    skip_whitespace(&s);
    
    if (s.pos >= s.length || !isalnum((unsigned char)s.expr[s.pos])) {
        result->detected_id = "INVALID-SPDX";
        result->type = LICENSE_INVALID;
        result->confidence = 0.1f;
        snprintf(result->notes, MAX_TEXT_SIZE, 
                 "Malformed SPDX expression");
        return false;
    }
    
    /* Parse first license ID */
    char id_buf[MAX_SPDX_EXPR_LEN];
    parse_spdx_id(&s, id_buf, sizeof(id_buf));
    
    if (id_buf[0] == '\0') {
        result->detected_id = "EMPTY-SPDX";
        result->type = LICENSE_INVALID;
        result->confidence = 0.1f;
        snprintf(result->notes, MAX_TEXT_SIZE, 
                 "Empty SPDX expression");
        return false;
    }
    
    /* Check if it's a valid SPDX ID */
    for (int i = 0; license_db[i].spdx_id != NULL; i++) {
        if (strcasecmp_n(license_db[i].spdx_id, id_buf) == 0) {
            result->detected_id = id_buf;
            result->type = LICENSE_PERMISSIVE; /* Default to permissive */
            result->confidence = license_db[i].confidence_threshold;
            
            /* Check for version constraints (or-later, etc.) */
            if (strstr(id_buf, "-or-later") != NULL) {
                snprintf(result->notes, MAX_TEXT_SIZE, 
                         "License with 'or-later' variant");
            } else if (strstr(id_buf, "-only") != NULL) {
                snprintf(result->notes, MAX_TEXT_SIZE, 
                         "Strict license version specified");
            }
            
            return true;
        }
    }
    
    /* Unknown SPDX ID */
    result->detected_id = id_buf;
    result->type = LICENSE_UNKNOWN;
    result->confidence = 0.4f;
    snprintf(result->notes, MAX_TEXT_SIZE, 
             "Unknown SPDX identifier: %s", id_buf);
    
    return true;
}

/* ============================================================================
 * Main Parser Interface
 */

int license_parse(const char *source_type, const char *content, ParseResult *result) {
    if (result == NULL || content == NULL) {
        result->detected_id = "NULL-INPUT";
        result->type = LICENSE_INVALID;
        result->confidence = 0.0f;
        snprintf(result->notes, MAX_TEXT_SIZE, 
                 "Null input provided");
        return -1;
    }
    
    /* Initialize result */
    memset(result, 0, sizeof(ParseResult));
    result->source = source_type ? source_type : "unknown";
    result->raw_content = content;
    result->content_len = (int)strlen(content);
    
    /* Determine parsing strategy based on source type */
    if (strcmp(source_type, "spdx") == 0) {
        return parse_spdx_expr(content, result);
    } else if (strcmp(source_type, "text_file") == 0 || 
               strcmp(source_type, "file") == 0) {
        return detect_license_from_text(content, result);
    } else if (strcmp(source_type, "metadata") == 0 ||
               strcmp(source_type, "json") == 0 ||
               strcmp(source_type, "yaml") == 0) {
        /* Extract license field from metadata */
        const char *license_field = strstr(content, "\"license\"");
        
        if (license_field != NULL) {
            /* Find the actual value - this is simplified parsing */
            const char *value_start = strchr(license_field, ':');
            if (value_start && *(value_start + 1) == '"') {
                value_start++;
                int depth = 0;
                while (*value_start && (depth > 0 || !isspace((unsigned char)*value_start))) {
                    if (*value_start == '"') depth--;
                    else if (*value_start == '"' && depth == 0) break;
                    value_start++;
                }
                
                if (strlen(value_start) > 0) {
                    return detect_license_from_text(value_start, result);
                }
            }
        }
        
        /* Fallback: search for license in metadata */
        return detect_license_from_text(content, result);
    } else {
        /* Default: treat as text file */
        return detect_license_from_text(content, result);
    }
}

/* ============================================================================
 * License Type Classification Helper
 */

LicenseType classify_license(const char *spdx_id) {
    if (spdx_id == NULL || spdx_id[0] == '\0') {
        return LICENSE_UNKNOWN;
    }
    
    /* Check against database first */
    for (int i = 0; license_db[i].spdx_id != NULL; i++) {
        if (strcasecmp_n(license_db[i].spdx_id, spdx_id) == 0) {
            return LICENSE_PERMISSIVE; /* Database entries are mostly permissive */
        }
    }
    
    /* Pattern-based classification for unknown licenses