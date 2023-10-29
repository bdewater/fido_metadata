# frozen_string_literal: true

require "fido_metadata/attributes"
require "fido_metadata/biometric_status_report"
require "fido_metadata/status_report"
require "fido_metadata/coercer/date"
require "fido_metadata/coercer/escaped_uri"
require "fido_metadata/coercer/objects"
require "fido_metadata/coercer/statement"

module FidoMetadata
  class Entry
    extend Attributes

    json_accessor("aaid")
    json_accessor("aaguid")
    json_accessor("attestationCertificateKeyIdentifiers")
    json_accessor("hash")
    json_accessor("url", Coercer::EscapedURI)
    json_accessor("biometricStatusReports", Coercer::Objects.new(BiometricStatusReport))
    json_accessor("statusReports", Coercer::Objects.new(StatusReport))
    json_accessor("timeOfLastStatusChange", Coercer::Date)
    json_accessor("rogueListURL", Coercer::EscapedURI)
    json_accessor("rogueListHash")
    json_accessor("metadataStatement", Coercer::Statement)
  end
end
