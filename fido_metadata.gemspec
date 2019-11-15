# frozen_string_literal: true

lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "fido_metadata/version"

Gem::Specification.new do |spec|
  spec.name          = "fido_metadata"
  spec.version       = FidoMetadata::VERSION
  spec.authors       = ["Bart de Water"]

  spec.summary       = "FIDO Alliance Metadata Service client"
  spec.description   = "Client for looking up metadata about FIDO authenticators, for use by WebAuthn relying parties"
  spec.homepage      = "https://github.com/bdewater/fido_metadata"
  spec.license       = "MIT"

  if spec.respond_to?(:metadata)
    spec.metadata["homepage_uri"] = spec.homepage
    spec.metadata["source_code_uri"] = spec.homepage
    spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/master/CHANGELOG.md"
  end

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.3"

  spec.add_dependency "jwt", "~> 2.0"
  spec.add_development_dependency "bundler", "~> 1.17"
  spec.add_development_dependency "pry-byebug"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.8"
  spec.add_development_dependency "rubocop", "0.75.0"
  spec.add_development_dependency "webmock", "~> 3.6"
end
