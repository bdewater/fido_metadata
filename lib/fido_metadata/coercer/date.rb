# frozen_string_literal: true

require "time"

module FidoMetadata
  module Coercer
    module Date
      def self.coerce(value)
        return value if value.is_a?(::Date)

        ::Date.iso8601(value) if value
      end
    end
  end
end
