# frozen_string_literal: true

require "fido_metadata/verification_method_descriptor"

module FidoMetadata
  module Coercer
    class UserVerificationDetails
      def self.coerce(values)
        return unless values.is_a?(Array)
        return values if values.all? do |array|
          array.all? do |object|
            object.is_a?(VerificationMethodDescriptor)
          end
        end

        values.map do |array|
          array.map do |hash|
            object = FidoMetadata::VerificationMethodDescriptor.from_json(hash)

            if hash["baDesc"]
              object.ba_desc = FidoMetadata::BiometricAccuracyDescriptor.from_json(hash["baDesc"])
            end
            if hash["caDesc"]
              object.ca_desc = FidoMetadata::CodeAccuracyDescriptor.from_json(hash["caDesc"])
            end
            if hash["paDesc"]
              object.pa_desc = FidoMetadata::PatternAccuracyDescriptor.from_json(hash["paDesc"])
            end

            object
          end
        end
      end
    end
  end
end
