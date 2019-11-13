# frozen_string_literal: true

require "fido_metadata/attributes"
require "fido_metadata/biometric_accuracy_descriptor"
require "fido_metadata/constants"
require "fido_metadata/code_accuracy_descriptor"
require "fido_metadata/pattern_accuracy_descriptor"
require "fido_metadata/coercer/magic_number"
require "fido_metadata/coercer/objects"

module FidoMetadata
  class VerificationMethodDescriptor
    extend Attributes

    json_accessor("userVerification", Coercer::MagicNumber.new(Constants::USER_VERIFICATION_METHODS))
    json_accessor("caDesc")
    json_accessor("baDesc")
    json_accessor("paDesc")
  end
end
