# frozen_string_literal: true

require "fido_metadata/store"
require "fido_metadata/version"

module FidoMetadata
  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  class Configuration
    attr_accessor :metadata_token
    attr_accessor :cache_backend
  end
end
