# frozen_string_literal: true

require "fido_metadata/attributes"
require "fido_metadata/verification_method_descriptor"
require "fido_metadata/coercer/assumed_value"
require "fido_metadata/coercer/bit_field"
require "fido_metadata/coercer/certificates"
require "fido_metadata/coercer/magic_number"
require "fido_metadata/coercer/user_verification_details"
require "fido_metadata/coercer/authenticator_get_info"

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
    json_accessor("authenticationAlgorithms")
    json_accessor("publicKeyAlgAndEncodings")
    json_accessor("attestationTypes")
    json_accessor("userVerificationDetails", Coercer::UserVerificationDetails)
    json_accessor("keyProtection")
    json_accessor("isKeyRestricted", Coercer::AssumedValue.new(true))
    json_accessor("isFreshUserVerificationRequired", Coercer::AssumedValue.new(true))
    json_accessor("matcherProtection")
    json_accessor("cryptoStrength")
    json_accessor("attachmentHint")
    json_accessor("tcDisplay")
    json_accessor("tcDisplayContentType")
    json_accessor("tcDisplayPNGCharacteristics")
    json_accessor("attestationRootCertificates")
    json_accessor("ecdaaTrustAnchors")
    json_accessor("icon")
    json_accessor("supportedExtensions")
    json_accessor("schema")
    json_accessor("authenticatorGetInfo", Coercer::AuthenticatorGetInfo)

    # Lazy load certificates for compatibility ActiveSupport::Cache. Can be removed once we require a version of
    # OpenSSL which includes https://github.com/ruby/openssl/pull/281
    def attestation_root_certificates
      Coercer::Certificates.coerce(@attestation_root_certificates)
    end

    def trust_store
      trust_store = OpenSSL::X509::Store.new
      attestation_root_certificates.each do |certificate|
        trust_store.add_cert(certificate)
      end
      trust_store
    end
  end
end
