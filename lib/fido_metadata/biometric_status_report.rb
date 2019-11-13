# frozen_string_literal: true

require "fido_metadata/attributes"
require "fido_metadata/coercer/date"

module FidoMetadata
  class BiometricStatusReport
    extend Attributes

    json_accessor("certLevel")
    json_accessor("modality")
    json_accessor("effectiveDate", Coercer::Date)
    json_accessor("certificationDescriptor")
    json_accessor("certificateNumber")
    json_accessor("certificationPolicyVersion")
    json_accessor("certificationRequirementsVersion")
  end
end
