# frozen_string_literal: true

require "fido_metadata/store"
require "fido_metadata/version"

module FidoMetadata
  def self.configuration
    @configuration ||= begin
      c = Configuration.new
      c.race_condition_ttl = 1
      c
    end
  end

  def self.configure
    yield(configuration)
  end

  class Configuration
    attr_accessor :metadata_token
    attr_accessor :cache_backend
    attr_accessor :race_condition_ttl
  end
end
