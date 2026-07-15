// polyglot/cpp/license_parser.cpp
// SPDX-License-Identifier: MIT
// License parser for licenselens - dependency license + SBOM gate

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <variant>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <regex>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace licenselens {

// SPDX License Expression Grammar Components
struct LicenseToken {
    enum class Type {
        Identifier,      // "MIT", "Apache-2.0"
        OperatorAnd,     // "AND"
        OperatorOr,      // "OR"
        OperatorWith,    // "WITH"
        ParenOpen,       // "("
        ParenClose,      // ")"
        Comma            // ","
    };
    
    Type type;
    std::string value;
};

struct LicenseExpression {
    enum class OpType {
        Single,          // Just a license ID
        And,             // AND operation
        Or,              // OR operation
        With             // WITH exception clause
    };
    
    OpType op = OpType::Single;
    std::string left;   // Left operand (license ID or expression)
    std::optional<std::string> right;  // Right operand for AND/OR/With
    
    static LicenseExpression from_token(const LicenseToken& tok) {
        LicenseExpression expr;
        expr.op = OpType::Single;
        expr.left = tok.value;
        return expr;
    }
};

// SPDX recognized license IDs (subset of common ones)
const std::set<std::string> KNOWN_LICENSE_IDS = {
    "0BSD", "AAL", "ADSL", "Afmpar", "AGPL-1.0-only", "AGPL-1.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later", "AMDPLPA", "AML", "AMPAS", "ANTLR-PD",
    "APAFML", "APL-1.0", "APSL-1.0", "APSL-1.1", "APSL-1.2", "APSL-2.0",
    "Arphic-1.0", "Artistic-1.0", "Artistic-1.0-test", "Artistic-2.0",
    "ASWF-Digital-Assets-1.0", "BaMIL", "BCL-1.1", "BSD-1-Clause",
    "BSD-2-Clause", "BSD-2-Clause-Patent", "BSD-3-Clause", "BSD-3-Clause-LBNL",
    "BSL-1.0", "BUSL-1.1", "CAL-1.0", "CAL-1.0-20040521", "CATOSL-1.1",
    "CC-BY-1.0", "CC-BY-2.0", "CC-BY-2.5", "CC-BY-3.0", "CC-BY-NC-1.0",
    "CC-BY-NC-2.0", "CC-BY-NC-2.5", "CC-BY-NC-3.0", "CC-BY-NC-ND-1.0",
    "CC-BY-NC-ND-2.0", "CC-BY-NC-ND-2.5", "CC-BY-NC-ND-3.0", "CC-BY-NC-SA-1.0",
    "CC-BY-NC-SA-2.0", "CC-BY-NC-SA-2.5", "CC-BY-NC-SA-3.0", "CC-BY-ND-1.0",
    "CC-BY-ND-2.0", "CC-BY-ND-2.5", "CC-BY-ND-3.0", "CC-BY-SA-1.0",
    "CC-BY-SA-2.0", "CC-BY-SA-2.5", "CC-BY-SA-3.0", "CC-PDDC-1.0",
    "CC0-1.0", "CDL-1.0", "CDLA-1.0", "CDLA-2.0", "CECILL-1.0",
    "CECILL-1.1", "CECILL-2.0", "CECILL-2.1", "CECILL-B-1.0",
    "CECILL-C-1.0", "CERN-OHL-1.0", "CERN-OHL-P-2.0", "CERN-OHL-S-2.0",
    "CERN-OHL-W-2.0", "CFITSIO-3.0", "CLISP-1.38", "CMU-Mach", "CNRI-Java",
    "CNRI-Python", "CNRI-Python-GPL-Compatible", "COIL-1.0", "Common-SGML",
    "CPAL-1.0", "CPL-1.0", "CPOL-1.02", "Crossword", "CSL-1.0",
    "CTPL-1.0", "CSS-2.0", "CUA-OPL-1.0", "CUDLL-1.0", "D-FSL-1.0",
    "DEC-3-Clause", "diffmark", "DocBook-1.0", "DocBook-2.0",
    "DocBook-2.0-tools", "DocBook-3.0", "Dotseqn", "DRL-1.0",
    "ECL-1.0", "ECL-2.0", "EFL-1.0", "EFL-2.0", "EFL-2.1",
    "ENGL-1.0", "EPICS", "EPL-1.0", "EPL-1.1", "EPL-2.0",
    "ERLPL-1.1", "EqUIP", "Entessa", "Eternity-PD", "ETL-1.0",
    "EUPL-1.0", "EUPL-1.1", "FADM-1.0", "FAR", "FASTER", "FDL-1.1",
    "FEDERA-1.0", "FSFAP", "FSFUL", "FSFULLR", "FTL", "Furuseth",
    "GFDL-1.1-only", "GFDL-1.1-or-later", "GFDL-1.2-only",
    "GFDL-1.2-or-later", "GFDL-1.3-only", "GFDL-1.3-or-later",
    "GL2PS-1.0", "GLUE-2.0", "GPL-1.0-only", "GPL-1.0-or-later",
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only",
    "GPL-3.0-or-later", "HPND", "HPND-PD", "HPND-sleepycat",
    "HSL", "HTMLTIDY", "IBM-pibs", "ICSI-1.0", "IEC-2.0",
    "IJG", "ImageMagick", "iMatix", "Imlib2", "INDIGO",
    "Intel-academic", "Interbase-1.0", "IPA", "IPD-1.0",
    "ISC", "Jam-1.0", "JasPer-2.0", "Kastrup", "Kazlib",
    "LAL-1.2", "LAL-1.3", "Latex2e", "Leptonica", "LiArt-2.0",
    "Libpng", "LibreSSL", "Linux-man-pages-1", "Linux-man-pages-copyleft",
    "Linux-man-pages-copyleft-1.1", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
    "LGPL-3.0-or-later", "LGPL-Latex2e", "Leptonica", "LPPL-1.0",
    "LPPL-1.1", "LPPL-1.2", "LPPL-1.3", "LRSL-1.0", "MPL-1.0",
    "MPL-1.1", "MPL-2.0", "MS-LPL-1.0", "MTLL", "Mup", "NAIST-2003",
    "NASA-1.3", "Naumen", "NBPL-1.0", "NCSA", "Net-SNMP",
    "NGPL", "NICTA-1.0", "NL-1.0", "NLOM-1.0", "NOSL",
    "NPL-1.0", "NPL-1.1", "NPOSL-3.0", "NRL", "NTP",
    "O-UDA-1.0", "OCCT-PL", "ODbL-1.0", "ODbl-1.0", "OFL-1.0",
    "OFL-1.0-a", "OFL-1.0-no-RFN", "OFL-1.1", "OFL-1.1-no-RFN",
    "OGC-1.0", "OGDL-Taiwan-1.0", "OGTSL-1.0", "OLDAP-1.1",
    "OLDAP-1.2", "OLDAP-1.3", "OLDAP-1.4", "OLDAP-2.0",
    "OLDAP-2.1", "OLDAP-2.2", "OLDAP-2.2.1", "OLDAP-2.2.2",
    "OLDAP-2.3", "OLDAP-2.4", "OLDAP-2.5", "OLDAP-2.6",
    "OLDAP-2.7", "OLDAP-2.8", "OML", "OpenAPI-2.0", "OPL-1.0",
    "OSL-1.0", "OSL-1.1", "OSL-2.0", "OSL-2.1", "OSL-3.0",
    "PADL", "PARI-GPL", "Parity-6.0-b", "PDDL-1.0", "PDFL-1.0",
    "PHP-3.0", "Phosphor-1.0", "PIAB-1.0", "PIRL", "PolyForm-Noncommercial-1.0.0",
    "PolyForm-Robert-Cosie-1.0.0", "PostgreSQL", "PSF-2.0",
    "Python-2.0", "Qhull", "QPL-1.0", "RPL-1.1", "RPL-1.5",
    "RSCPL", "RSA-MD", "RSCPL", "Ruby", "SAX-PD", "SCEA",
    "Sendmail", "SGI-B-1.0", "SGI-B-1.1", "SGI-B-2.0",
    "SGPPL", "SHL-2.0", "SimPL-2.0", "SISSL-3.0", "SL-1.0",
    "Sleepycat", "SMLNJ", "SMPPL", "SNIA", "Spencer-86",
    "SPDX-Permissive-1.0", "SPDX-Standard-1.0", "SSPL-1.0",
    "SugarCRM-1.1.3", "SWL-1.0", "TAPR-OHL-1.0", "TCL",
    "TCP-wrappers", "TD-1.0", "TEOS-1.0", "TGFD-1.0",
    "THREEJS", "TORQUE-1.0", "TPH2-1.0", "TPL-1.0", "TSL-1.1",
    "TVML", "UCL-1.0", "UCL-1.0", "Unicode-DFS-2015",
    "Unicode-DFS-2016", "Unicode-3.0", "Unicode-3.0-js",
    "Unicode-3.1", "Unicode-3.2", "Unicode-Draft-3.2",
    "Unicode-4.0", "UPL-1.0", "Vim", "W3C", "W3C-19980702",
    "W3C-20150513", "W3C-20150526", "W3C-20150607",
    "W3C-20150929", "W3C-20151214", "W3M", "Watcom-1.0",
    "Wsuipa", "WTFPL", "X11", "Xdebug-1.0", "Xerox",
    "Xfig-1.3", "xinetd", "Xlock", "Xnet", "XPM",
    "Zlib", "ZPL-1.1", "ZPL-2.0", "ZPL-2.1"
};

// Parse a single license identifier (e.g., "MIT", "Apache-2.0")
std::optional<LicenseExpression> parse_license_identifier(const std::string& token) {
    // Trim whitespace
    auto trimmed = token;
    while (!trimmed.empty() && std::isspace(trimmed.front())) {
        trimmed.erase(0, 1);
    }
    while (!trimmed.empty() && std::isspace(trimmed.back())) {
        trimmed.pop_back();
    }
    
    if (trimmed.empty()) return std::nullopt;
    
    // Check for WITH clause
    auto with_pos = trimmed.find("WITH");
    if (with_pos != std::string::npos) {
        LicenseExpression expr;
        expr.op = OpType::With;
        
        // Left side is the main license
        std::string left = trimmed.substr(0, with_pos);
        while (!left.empty() && std::isspace(left.back())) {
            left.pop_back();
        }
        
        // Right side is the exception
        std::string right = trimmed.substr(with_pos + 4);
        while (!right.empty() && std::isspace(right.front())) {
            right.erase(0, 1);
        }
        while (!right.empty() && std::isspace(right.back())) {
            right.pop_back();
        }
        
        expr.left = left;
        expr.right = right;
        return expr;
    }
    
    // Check if it's a known license ID
    auto it = KNOWN_LICENSE_IDS.find(trimmed);
    if (it != KNOWN_LICENSE_IDS.end()) {
        LicenseExpression expr;
        expr.op = OpType::Single;
        expr.left = trimmed;
        return expr;
    }
    
    // Unknown identifier - still accept it but mark as unknown
    LicenseExpression expr;
    expr.op = OpType::Single;
    expr.left = trimmed;
    return expr;
}

// Tokenize a license expression string
std::vector<LicenseToken> tokenize_expression(const std::string& expr_str) {
    std::vector<LicenseToken> tokens;
    
    // Remove outer parentheses if present
    bool has_outer_parens = false;
    if (!expr_str.empty() && expr_str.front() == '(' && 
        !expr_str.empty() - 1 && expr_str.back() == ')') {
        expr_str.erase(0, 1);
        expr_str.pop_back();
        has_outer_parens = true;
    }
    
    // Tokenize character by character
    for (size_t i = 0; i < expr_str.length(); ++i) {
        char c = expr_str[i];
        
        if (std::isalnum(c) || c == '-'