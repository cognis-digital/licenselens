require 'json'
require 'uri'

module Licenselens
  # SPDX identifiers that are commonly encountered
  COMMON_SPDX_IDS = {
    "MIT" => "MIT",
    "MIT License" => "MIT",
    "Apache-2.0" => "Apache-2.0",
    "Apache 2.0" => "Apache-2.0",
    "BSD-3-Clause" => "BSD-3-Clause",
    "ISC" => "ISC",
    "GPL-3.0-only" => "GPL-3.0-only",
    "LGPL-2.1-only" => "LGPL-2.1-only",
    "MPL-2.0" => "MPL-2.0",
    "Zlib" => "Zlib",
    "WTFPL" => "WTFPL",
  }.freeze

  # License families for grouping similar licenses
  LICENSE_FAMILIES = {
    "MIT" => ["MIT", "X11"],
    "Apache-2.0" => ["Apache-2.0", "Apache-2.1"],
    "BSD" => ["BSD-2-Clause", "BSD-3-Clause", "BSD-Protection"],
    "GPL" => ["GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1-only"],
  }.freeze

  # Maximum reasonable license text length (in characters)
  MAX_LICENSE_LENGTH = 50_000

  # Confidence thresholds
  CONFIDENCE_HIGH = 0.9
  CONFIDENCE_MEDIUM = 0.7
  CONFIDENCE_LOW = 0.4

  class LicenseParser
    attr_reader :input, :confidence, :warnings

    def initialize(input: nil)
      @input = input || ""
      @warnings = []
    end

    # Main parsing entry point
    def parse
      result = {
        name: extract_name,
        spdx_id: extract_spdx_id,
        text: extract_text,
        source_url: extract_source_url,
        version: extract_version,
        family: detect_family,
        confidence: calculate_confidence,
        warnings: @warnings.dup,
      }

      result[:text] = truncate_text(result[:text]) if result[:text].present? && result[:text].length > MAX_LICENSE_LENGTH

      result
    end

    private

    def extract_name
      # Try to find a license name from various patterns
      text_cleaned = @input.to_s.strip.downcase

      # Check for SPDX ID first (most reliable)
      return COMMON_SPDX_IDS.keys.first if COMMON_SPDX_IDS.keys.any? { |id| text_cleaned.include?(id) }

      # Look for common license headers
      header_patterns = [
        /(\w+[-\s]License)/i,
        /\b(mit|apache\s*2\.0|bsd-3|gpl-3)\.?\b/i,
        /copyright\s+(?:the\s+)?(mit|apache|bsd|isc|mpl|lGPL|EPL)[\-\s]*license/i,
      ]

      header_patterns.each do |pattern|
        match = text_cleaned.match(pattern)
        return match[1].strip if match
      end

      # Fallback: extract from HTML meta tags or data attributes
      html_name = extract_html_license_name
      return html_name unless html_name.nil?

      "Unknown"
    end

    def extract_spdx_id
      text_cleaned = @input.to_s.strip.downcase

      # Direct SPDX ID match
      COMMON_SPDX_IDS.keys.each do |id|
        if text_cleaned.include?(id)
          return id
        end
      end

      # Try to find in HTML metadata
      html_spdx = extract_html_spdx_id
      return html_spdx unless html_spdx.nil?

      nil
    end

    def extract_text
      return @input.to_s.strip if !@input.is_a?(String) || @input.include?("<")

      # For plain text, just normalize whitespace
      @input.to_s.gsub(/\s+/, " ").strip
    end

    def extract_source_url
      # Look for URLs in HTML that might point to license info
      if @input.is_a?(String) && @input.include?("<")
        url_match = /data-licenselens-url="([^"]+)"/i.match?(@input)
        return url_match[1] if url_match

        # Also check for standard npm/pip metadata URLs
        url_patterns = [
          /url\s*=\s*['"]?(https?:\/\/[^'"]+)(?:['"]|;)/i,
          /data-licenselens-url="([^"]+)"/i,
        ]

        url_patterns.each do |pattern|
          match = @input.match(pattern)
          return match[1] if match
        end
      end

      nil
    end

    def extract_version
      # Look for version in HTML metadata or data attributes
      if @input.is_a?(String) && @input.include?("<")
        # Check for common npm/pip version fields
        return /data-licenselens-version="([^"]+)"/i.match(@input)&.[](1)

        # Look for semver patterns in text content
        if !@input.is_a?(String) || @input.include?("<")
          return nil
        end

        # Check for version-like patterns near license headers
        version_patterns = [
          /(\w+[-\s]License)[\s\S]{0,150}([^\s<>"']+\.?[0-9][^<>\s"]+)/i,
          /version\s*=\s*['"]?([^'"\s]+)['"]?\s*(?:license|name)/i,
        ]

        version_patterns.each do |pattern|
          match = @input.match(pattern)
          if match && match[2] && !match[2].include?("License")
            return match[2].strip unless COMMON_SPDX_IDS.keys.include?(match[2])
          end
        end
      end

      nil
    end

    def extract_html_license_name
      # Extract from HTML metadata attributes
      if @input.is_a?(String) && @input.include?("<")
        return /data-licenselens-name="([^"]+)"/i.match(@input)&.[](1)
      end

      nil
    end

    def extract_html_spdx_id
      # Extract SPDX ID from HTML metadata
      if @input.is_a?(String) && @input.include?("<")
        return /data-licenselens-spdx-id="([^"]+)"/i.match(@input)&.[](1)
      end

      nil
    end

    def detect_family
      spdx_id = extract_spdx_id
      return "Unknown" if spdx_id.nil?

      COMMON_SPDX_IDS.keys.each do |known|
        family = LICENSE_FAMILIES[known]
        return family.first if family && family.include?(spdx_id)
      end

      # If not in our known families, try to infer from name
      text_cleaned = @input.to_s.strip.downcase
      "Unknown"
    end

    def calculate_confidence
      score = 0.0
      max_score = 10.0

      # Exact SPDX ID match (highest confidence)
      if COMMON_SPDX_IDS.keys.any? { |id| @input.to_s.include?(id) }
        score += 3.0
      end

      # HTML metadata present
      if @input.is_a?(String) && @input.include?("<")
        if /data-licenselens-name/i.match?(@input) || /data-licenselens-spdx-id/i.match?(@input)
          score += 2.0
        end
        # Check for standard package manager metadata
        score += 1.0 if /<meta\s+name=["']?license["']?\s+content=["'][^"']+["']/i.match?(@input)
      end

      # License header patterns found
      license_headers = [
        /(\w+[-\s]License)/i,
        /\b(mit|apache\s*2\.0|bsd-3|gpl-3)\.?\b/i,
      ]

      license_headers.each do |pattern|
        score += 1.0 if @input.to_s.match?(pattern)
      end

      # Text length (very short might be truncated)
      text_len = @input.to_s.length
      if text_len < 50 && !@input.is_a?(String) || @input.include?("<")
        score += 1.0
      elsif text_len > 200
        score += 2.0
      end

      # Normalize to 0-1 range
    end

    def truncate_text(text, max_length = MAX_LICENSE_LENGTH)
      return text if !text.is_a?(String) || text.length <= max_length

      "#{text[0..max_length]}..."
    end
  end
end

# ==================== DEMO / ENTRY POINT ====================

if __FILE__ == $PROGRAM_NAME
  require 'bundler/setup' rescue nil

  # Sample inputs for testing
  SAMPLES = [
    {
      name: "Plain MIT License",
      input: <<~TEXT,
        MIT License

        Copyright (c) 2023 Example Corp.

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.
      TEXT
    },
    {
      name: "npm HTML metadata",
      input: <<~HTML,
        <div data-licenselens-name="MIT License" data-licenselens-spdx-id="MIT" data-licenselens-version="1.0.0">
          <meta name="license" content="MIT"/>
        </div>
      HTML
    },
    {
      name: "Apache 2.0 (partial)",
      input: <<~TEXT,
        Apache License 2.0

        Copyright 2023 Example Corp.

        Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at:

          http://www.apache.org/licenses/LICENSE-2.0
      TEXT
    },
    {
      name: "Empty input",
      input: "",
    },
    {
      name: "HTML with URL metadata",
      input: <<~HTML,
        <div data-licenselens-name="BSD-3-Clause" data-licenselens-spdx-id="BSD-3-Clause" data-licenselens-url="https://opensource.org/licenses/BSD-3-Clause">
          BSD 3-Clause License
        </div>
      HTML
    },
  ]

  puts "=" * 70
  puts "Licenselens::LicenseParser Demo"
  puts "=" * 70
  puts

  SAMPLES.each do |sample|
    puts "Sample: #{sample[:name]}"
    puts "-" * 40

    parser = Licenselens::LicenseParser.new(input: sample[:input])
    result = parser.parse

    puts "Name:        #{result[:name].inspect}"
    puts "SPDX ID:     #{result[:spdx_id].inspect}"
    puts "Family:      #{result[:family].inspect}"
    puts "Confidence:  #{(result[:confidence] * 100).round(1)}%"
    puts "Warnings:    #{result[:warnings].join(", ") rescue ""}"

    if result[:text].present? && result[:text].length > 50
      puts "Text preview: #{result[:text][0..100]}..."
    end

    puts
  end

  # Test with a real-world-ish HTML snippet
  puts "=" * 70
  puts "Real-world HTML test"
  puts "=" * 70

  real_html = <<~HTML
    <div class="license-info">
      <meta name="data-licenselens-name" content="MIT License"/>
      <meta name="data-licenselens-spdx-id" content="MIT"/>
      <meta name="data-licenselens-version" content="1.0.3"/>
      <meta name="data-licenselens-url" content="https://opensource.org/licenses/MIT"/>
      
      <div class="license-text">
        MIT License

        Copyright (c) 2024 Example Corporation. All rights reserved.

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.
      </div>
    </div>
  HTML

  parser = Licenselens::LicenseParser.new(input: real_html)
  result = parser.parse

  puts "Parsed Result:"
  puts JSON.pretty_generate(result)
end