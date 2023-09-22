# frozen_string_literal: true

require "fido_metadata/authenticator_get_info"

module FidoMetadata
  module Coercer
    module AuthenticatorGetInfo
      def self.coerce(value)
        return value if value.is_a?(FidoMetadata::AuthenticatorGetInfo)

        FidoMetadata::AuthenticatorGetInfo.from_json(value) if value
      end
    end
  end
end
