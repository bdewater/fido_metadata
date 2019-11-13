# frozen_string_literal: true

require "fido_metadata/attributes"
require "fido_metadata/coercer/date"
require "fido_metadata/coercer/escaped_uri"

module FidoMetadata
  class StatusReport
    extend Attributes

    json_accessor("status")
    json_accessor("effectiveDate", Coercer::Date)
    json_accessor("certificate")
    json_accessor("url", Coercer::EscapedURI)
    json_accessor("certificationDescriptor")
    json_accessor("certificateNumber")
    json_accessor("certificationPolicyVersion")
    json_accessor("certificationRequirementsVersion")
  end
end
