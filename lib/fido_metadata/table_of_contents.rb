# frozen_string_literal: true

require "fido_metadata/attributes"
require "fido_metadata/entry"
require "fido_metadata/coercer/date"
require "fido_metadata/coercer/objects"

module FidoMetadata
  class TableOfContents
    extend Attributes

    json_accessor("legalHeader")
    json_accessor("nextUpdate", Coercer::Date)
    json_accessor("entries", Coercer::Objects.new(Entry))
    json_accessor("no")

    def expires_in
      next_update.to_time.to_i - Time.now.to_i
    end
  end
end
