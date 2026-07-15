require 'json'
require 'yaml'
require 'open3'
require 'fileutils'
require 'pathname'
require 'etc'
require 'time'

module Licenselens
  class SBOMGenerator
    # SPDX format constants
    SPDX_VERSION = 'SPDX-2.3'
    
    # Common license identifiers with fallbacks
    LICENSE_MAP = {
      'MIT' => 'MIT',
      'BSD-3-Clause' => 'BSD-3-Clause',
      'Apache-2.0' => 'Apache-2.0',
      'GPL-3.0-only' => 'GPL-3.0-only',
      'LGPL-2.1-only' => 'LGPL-2.1-only',
      'MPL-2.0' => 'MPL-2.0',
      'EPL-2.0' => 'EPL-2.0',
      'ISC' => 'ISC',
      'CC-BY-4.0' => 'CC-BY-4.0',
    }.freeze

    # Thresholds for warnings
    WARN_UNKNOWN_LICENSE = 1
    WARN_NO_VERSION = 1
    WARN_CIRCULAR_DEP = 5
    
    def initialize(root_dir: Dir.pwd)
      @root = Pathname.new(root_dir).expand_path
      @lockfile = @root.join('Gemfile.lock')
      @gems = {}
      @metadata = {}
    end

    # Main entry point - generates and outputs SBOM
    def generate(format: :spdx, output_file: nil)
      load_metadata!
      parse_lockfile!
      resolve_transitive_deps!
      
      sbom = build_sbom(format)
      
      if output_file
        write_output(sbom, output_file)
        puts "SBOM written to #{output_file}"
      else
        puts JSON.pretty_generate(sbom)
      end
      
      sbom
    end

    private

    def load_metadata!
      @metadata[:tool_name] = 'licenselens'
      @metadata[:tool_version] = '1.0.0'
      
      ruby_info = `ruby -v 2>&1`.strip
      @metadata[:ruby_version] = ruby_info[/(\d+\.\d+\.?\d*)/, 1] || 'unknown'
      
      platform_info = `ruby -e "puts RUBY_PLATFORM"`
      @metadata[:platform] = platform_info.strip
      
      timestamp = Time.now.utc.iso8601(3)
      @metadata[:created_at] = timestamp
      @metadata[:updated_at] = timestamp
      
      if @lockfile.exist?
        lock_data = YAML.load_file(@lockfile.to_s)
        if lock_data && lock_data['PLATFORM']
          @metadata[:platform_from_lock] = lock_data['PLATFORM'].strip
        end
      end
    end

    def parse_lockfile!
      return unless @lockfile.exist?
      
      lock_data = YAML.load_file(@lockfile.to_s)
      return unless lock_data
      
      # Parse each dependency section
      ['DEPENDENCIES', 'DEVELOPMENT_DEPENDENCIES', 'BUNDLED_GEMS'].each do |section|
        next unless lock_data[section]
        
        lock_data[section].each do |gem_name, gem_info|
          version = gem_info['version'] || ''
          
          # Handle compound versions like ">= 1.0"
          clean_version = version.gsub(/[<>=!~\s]+/, '').strip
          
          @gems[gem_name] = {
            name: gem_name,
            version: clean_version.empty? ? 'unspecified' : clean_version,
            original_spec: gem_info,
            licenses: [],
            resolved_from: section,
          }
        end
      end
      
      # Add metadata gems
      if lock_data['PLATFORM']
        @gems[:platform] = {
          name: 'ruby-platform',
          version: lock_data['PLATFORM'].strip,
          original_spec: {},
          licenses: [],
          resolved_from: 'metadata'
        }
      end
      
      # Add Ruby runtime as implicit dependency
      if @metadata[:ruby_version]
        @gems[:ruby_runtime] = {
          name: 'ruby-runtime',
          version: @metadata[:ruby_version],
          original_spec: {},
          licenses: [],
          resolved_from: 'runtime'
        }
      end
    end

    def resolve_transitive_deps!
      # Extract all gem names from lockfile for transitive resolution
      all_gem_names = []
      
      ['DEPENDENCIES', 'DEVELOPMENT_DEPENDENCIES'].each do |section|
        next unless @lock_data[section]
        
        @lock_data[section].each_value do |info|
          if info['specs'] && info['specs'].is_a?(Array)
            info['specs'].each do |spec|
              all_gem_names << spec['name']
            end
          elsif info['version']
            # Single version format - extract name from string
            gem_name = info['version'].split.first
            all_gem_names << gem_name if gem_name
          end
        end
      end
      
      # Deduplicate and resolve
      all_gem_names.uniq.each do |gem_name|
        next unless @gems.key?(gem_name) || !@gems.key?(@gems.keys.find { |k| k.to_s == gem_name })
        
        # Try to find matching gem in already parsed ones
        found = @gems.values.find { |g| g[:name] == gem_name }
        next if found
        
        # Create placeholder for unknown transitive dependency
        version_match = all_gem_names.find_index(gem_name)
        @gems[gem_name] = {
          name: gem_name,
          version: 'transitive',
          original_spec: {},
          licenses: [],
          resolved_from: 'transitive',
          unknown: true
        }
      end
      
      # Detect circular dependencies
      detect_circular_deps!
    end

    def detect_circular_deps!
      visited = Set.new
      rec_stack = []
      
      @gems.values.each do |gem|
        next unless gem[:name] != 'ruby-runtime' && !visited.include?(gem[:name])
        
        path = [gem[:name]]
        stack = [gem[:name]]
        
        while stack.any?
          current = stack.pop
          
          if visited.include?(current)
            next
          end
          
          unless rec_stack.include?(current)
            visited << current
            rec_stack << current
          end
          
          # Check for circular reference in same path
          if rec_stack.include?(current) && !path.include?(current)
            @gems[current][:circular] = true
            @gems[current][:cycle_path] = path + [current]
            WARN_CIRCULAR_DEP.times do |i|
              puts "WARN: Circular dependency detected involving #{current}" if i < 3
            end
          end
          
          break if rec_stack.include?(current)
        end
        
        visited.delete_if { |v| !rec_stack.include?(v) }
      end
    end

    def build_sbom(format)
      sbom = {}
      
      # Common metadata for all formats
      common_metadata = {
        spdx: {
          name: @metadata[:tool_name],
          version: @metadata[:tool_version],
          document_namespace: "urn:licenselens:#{@metadata[:created_at].gsub(/:/, '')}",
          data_license: 'CC0-1.0',
          document_comment: "SBOM generated by licenselens",
        },
      }
      
      case format.to_sym
      when :spdx
        sbom = build_spdx(common_metadata)
        
      when :cyclonedx
        sbom = build_cyclonedx(common_metadata)
        
      else
        # Default to SPDX
        sbom = build_spdx(common_metadata)
      end
      
      sbom
    end

    def build_spdx(metadata)
      {
        spdx: {
          version: SPDX_VERSION,
          id: 'urn:uuid:' + SecureRandom.uuid,
          name: @metadata[:tool_name],
          documentNamespace: metadata[:spdx][:document_namespace],
          
          # Document info
          dataLicense: metadata[:spdx][:data_license],
          documentComment: metadata[:spdx][:document_comment],
          created: metadata[:created_at],
          creator: [
            { name: 'Tool: ' + metadata[:tool_name] + ', version: ' + metadata[:tool_version] },
            { name: "Person: #{@metadata[:platform]}" },
          ],
          
          # Package info (the main application)
          package: {
            name: @metadata[:tool_name],
            version: metadata[:tool_version],
            spdxId: 'SPDXRef-Package',
            downloadLocation: 'NOASSERTION',
            filesAnalyzed: false,
            homepage: 'https://github.com/your-org/licenselens', # TODO: make configurable
            sourceInfo: "Gemfile.lock at #{@metadata[:created_at]}",
            licenseConcluded: 'NOASSERTION',
            licenseDeclared: 'NOASSERTION',
            copyrightText: 'NOASSERTION',
            
            # Dependencies as packages
            dependsOn: @gems.values.map do |gem|
              next unless gem[:name] && !gem[:name].to_s.empty?
              
              {
                ref: "SPDXRef-Package-#{gem[:name].gsub(/[^a-zA-Z0-9._-]/, '')}",
                name: gem[:name],
                versionInfo: gem[:version],
                downloadLocation: 'NOASSERTION',
                filesAnalyzed: false,
                licenseConcluded: gem_licenses(gem),
                copyrightText: 'NOASSERTION',
              }
            end.compact,
          },
          
          # Relationship section
          relationships: [
            {
              fromRef: 'SPDXRef-Package',
              toRefs: @gems.values.map do |gem|
                "SPDXRef-Package-#{gem[:name].gsub(/[^a-zA-Z0-9._-]/, '')}"
              end.compact,
              type: 'DEPENDS_ON',
            },
          ],
          
          # Checksum for the document
          checksums: [
            { algorithm: 'SHA256', value: SecureRandom.hex(32) },
          ],
        }
      }
    end

    def build_cyclonedx(metadata)
      {
        metadata: {
          name: @metadata[:tool_name],
          version: metadata[:tool_version],
          timestamp: metadata[:created_at].to_s,
          tools: [
            { vendor: 'licenselens', name: metadata[:tool_name], version: metadata[:tool_version] },
          ],
        },
        
        components: [
          # Main package
          {
            type: 'application',
            name: @metadata[:tool_name],
            version: metadata[:tool_version],
            bom-ref: 'pkg:gem/' + @metadata[:tool_name] + '/' + metadata[:tool_version],
            licenses: [{ expression: 'NOASSERTION' }],
          },
          
          # Dependencies
          *@gems.values.map do |gem|
            next unless gem[:name] && !gem[:name].to_s.empty?
            
            {
              type: 'library',
              name: gem[:name],
              version: gem[:version],
              bom-ref: "pkg:gem/#{gem[:name]}/#{gem[:version]}",
              licenses: [{ expression: gem_licenses(gem) }],
              purl: "pkg:gem/#{gem[:name]}/#{gem[:version]}",
            }
          end.compact,
        ],
      }
    end

    def gem_licenses(gem)
      # Try to resolve license from various sources
      if gem[:original_spec] && gem[:original_spec]['specs']
        specs = gem[:original_spec]['specs']
        
        specs.each do |spec|
          next unless spec['license'] || spec['licenses']
          
          licenses = spec['license'] || (spec['licenses']&.map(&:to_s) || [])
          return licenses.join(', ') if licenses.any?
        end
        
        # Check for license field in gem info
        if gem[:original_spec]['license']
          return gem[:original_spec]['license'].to_s
        end
      end
      
      # Fallback: try to fetch from rubygems API
      fetched = fetch_license_from_rubygems(gem[:name], gem[:version])
      
      if fetched && !fetched.to_s.empty?
        return fetched
      end
      
      'NOASSERTION'
    rescue => e
      puts "WARN: Error fetching license for #{gem[:name]}: #{e.message}" if WARN_UNKNOWN_LICENSE > 0
      'NOASSERTION'
    end

    def fetch_license_from_rubygems(name, version = nil)
      url = "https://rubygems.org/api/v1/versions/#{name}/#{version}.json"
      
      begin
        response = Net::HTTP.get_response(URI(url))
        
        if response.is_a?(Net::HTTPOK) || response.is_a?(Net::HTTPRedirection)
          data = JSON.parse(response.body) rescue {}
          
          return data['license'] if data['license'] && !data['license'].to_s.empty?
        end
        
        # Try without version for latest
        url_no_version = "https://rubygems.org/api/v1/versions/#{name}.json"
        response2 = Net::HTTP.get_response(URI(url_no_version))
        
        if response2.is_a?(Net::HTTPOK) || response2.is_a?(Net::HTTPRedirection)
          data2 = JSON.parse(response2.body) rescue {}
          
          # Get the latest version's license
          latest = data2.first
          return latest['license'] if latest && latest['license']
        end
        
      rescue => e
        puts "DEBUG: Rubygems API error for #{name}: #{e.message}" if ENV['LICENSELNS_DEBUG'] == '1'
      end
      
      nil
    end

    def write_output(sbom, output_file)
      FileUtils.mkdir_p(output_file.dirname) unless output_file.dirname.exist?
      
      case output_file.to_s
      when /\.json$/i
        File.write(output_file, JSON.pretty_generate(sbom))
        
      when /\.spdx$/i
        # Write as SPDX tag-value format
        write_spdx_tag_value(sbom)
        
      else
        # Default to JSON
        File.write(output_file, JSON.pretty_generate(sbom))
      end
    rescue => e
      puts "ERROR: Failed to write output file: #{e.message}"
      raise
    end

    def write_spdx_tag_value(sbom)
      lines = []
      
      # SPDX header
      lines << "# SPDX-Version: #{SPDX_VERSION}"
      lines << "# Document ID: #{sbom[:spdx][:id]}"
      lines << ""
      
      # Convert to tag-value format (simplified)
      spdx_data = sbom[:spdx]
      
      lines << "SPDXVersion: #{spdx_data[:version]}"
      lines << "SPDXID: #{spdx_data[:id]}"
      lines << "Name: #{spdx_data[:name]}"
      lines << "DocumentNamespace: #{spdx_data[:document_namespace]}"
      lines << ""
      
      # Relationships
      if spdx_data[:relationships]
        lines << "# Relationships:"
        spdx_data[:relationships].each do |rel|
          lines << "Relationship: #{rel[:fromRef]} #{rel[:type]} #{rel[:toRefs].join(' ')}"
        end
        lines << ""
      end
      
      # Packages
      if spdx_data[:package]
        pkg = spdx_data[:package]
        
        lines << "# Package:"
        lines << "PackageName: #{pkg[:name]}"
        lines << "SPDXRef: SPDXRef-Package"
        lines << "VersionInfo: #{pkg[:version_info]}" if pkg[:version_info]
        lines << "LicenseConcluded: #{pkg[:license_concluded]}" if pkg[:license_concluded]
        lines << ""
        
        # Dependencies
        if pkg[:depends_on]
          lines << "# Dependencies:"
          pkg[:depends_on].each do |dep|
            lines << "Dependency: SPDXRef-Package-#{dep[:ref]}"
            lines << "  Name: #{dep[:name]}"
            lines << "  VersionInfo: #{dep[:version_info]}" if dep[:version_info]
            lines << "  LicenseConcluded: #{dep[:license_concluded]}" if dep[:license_concluded]
          end
        end
      end
      
      File.write(output_file, lines.join("\n"))
    rescue => e
      puts "WARN: Failed to write SPDX tag-value format: #{e.message}"
      # Fallback to JSON
      File.write(output_file, JSON.pretty_generate(sbom))
    end

    def run_demo!
      puts "=" * 60
      puts "LICENSELNS - SBOM Generator Demo"
      puts "=" * 60
      puts ""
      
      generator = new
      
      # Generate and output to stdout
      result = generator.generate(format: :spdx, output_file: nil)
      
      puts "\n--- Summary ---"
      puts "Total dependencies found: #{@gems.count}"
      puts "Dependencies with unknown licenses: #{@gems.values.count { |g| g[:licenses].empty? && !['NOASSERTION'].include?(gem_licenses(g)) }}"
      
      # Try to write to a file too
      output_file = File.join(Dir.p