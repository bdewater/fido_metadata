# frozen_string_literal: true

require "fido_metadata/attributes"

module FidoMetadata
  class PatternAccuracyDescriptor
    extend Attributes

    json_accessor("minComplexity")
    json_accessor("maxRetries")
    json_accessor("blockSlowdown")
  end
end
