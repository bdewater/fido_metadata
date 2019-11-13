# frozen_string_literal: true

require "fido_metadata/attributes"

module FidoMetadata
  class CodeAccuracyDescriptor
    extend Attributes

    json_accessor("base")
    json_accessor("minLength")
    json_accessor("maxRetries")
    json_accessor("blockSlowdown")
  end
end
