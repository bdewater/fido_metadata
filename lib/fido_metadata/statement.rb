# frozen_string_literal: true

require "fido_metadata/attributes"
require "fido_metadata/constants"
require "fido_metadata/verification_method_descriptor"
require "fido_metadata/coercer/assumed_value"
require "fido_metadata/coercer/bit_field"
require "fido_metadata/coercer/certificates"
require "fido_metadata/coercer/magic_number"
require "fido_metadata/coercer/user_verification_details"

module FidoMetadata
  class Statement
    extend Attributes

    json_accessor("legalHeader")
    json_accessor("aaid")
    json_accessor("aaguid")
    json_accessor("attestationCertificateKeyIdentifiers")
    json_accessor("description")
    json_accessor("alternativeDescriptions")
    json_accessor("authenticatorVersion")
    json_accessor("protocolFamily", Coercer::AssumedValue.new("uaf"))
    json_accessor("upv")
    json_accessor("assertionScheme")
    json_accessor("authenticationAlgorithm", Coercer::MagicNumber.new(Constants::AUTHENTICATION_ALGORITHMS))
    json_accessor("authenticationAlgorithms",
                  Coercer::MagicNumber.new(Constants::AUTHENTICATION_ALGORITHMS, array: true))
    json_accessor("publicKeyAlgAndEncoding", Coercer::MagicNumber.new(Constants::PUBLIC_KEY_FORMATS))
    json_accessor("publicKeyAlgAndEncodings",
                  Coercer::MagicNumber.new(Constants::PUBLIC_KEY_FORMATS, array: true))
    json_accessor("attestationTypes", Coercer::MagicNumber.new(Constants::ATTESTATION_TYPES, array: true))
    json_accessor("userVerificationDetails", Coercer::UserVerificationDetails)
    json_accessor("keyProtection", Coercer::BitField.new(Constants::KEY_PROTECTION_TYPES))
    json_accessor("isKeyRestricted", Coercer::AssumedValue.new(true))
    json_accessor("isFreshUserVerificationRequired", Coercer::AssumedValue.new(true))
    json_accessor("matcherProtection",
                  Coercer::BitField.new(Constants::MATCHER_PROTECTION_TYPES, single_value: true))
    json_accessor("cryptoStrength")
    json_accessor("operatingEnv")
    json_accessor("attachmentHint", Coercer::BitField.new(Constants::ATTACHMENT_HINTS))
    json_accessor("isSecondFactorOnly")
    json_accessor("tcDisplay", Coercer::BitField.new(Constants::TRANSACTION_CONFIRMATION_DISPLAY_TYPES))
    json_accessor("tcDisplayContentType")
    json_accessor("tcDisplayPNGCharacteristics")
    json_accessor("attestationRootCertificates")
    json_accessor("ecdaaTrustAnchors")
    json_accessor("icon")
    json_accessor("supportedExtensions")

    # Lazy load certificates for compatibility ActiveSupport::Cache. Can be removed once we require a version of
    # OpenSSL which includes https://github.com/ruby/openssl/pull/281
    def attestation_root_certificates
      Coercer::Certificates.coerce(@attestation_root_certificates)
    end
  end
end
