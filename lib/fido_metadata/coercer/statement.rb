# frozen_string_literal: true

require "fido_metadata/statement"

module FidoMetadata
  module Coercer
    module Statement
      def self.coerce(value)
        return value if value.is_a?(FidoMetadata::Statement)

        FidoMetadata::Statement.from_json(value) if value
      end
    end
  end
end
