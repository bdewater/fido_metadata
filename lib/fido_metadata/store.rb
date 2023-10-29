# frozen_string_literal: true

require "fido_metadata/client"
require "fido_metadata/table_of_contents"
require "fido_metadata/statement"

module FidoMetadata
  class Store
    METADATA_ENDPOINT = URI("https://mds.fidoalliance.org/")

    def table_of_contents
      @table_of_contents ||= begin
        key = "metadata_toc"
        toc = cache_backend.read(key)
        return toc if toc

        json = client.download_toc(METADATA_ENDPOINT)
        toc = FidoMetadata::TableOfContents.from_json(json)
        cache_backend.write(key, toc)
        toc
      end
    end

    def fetch_entry(aaguid: nil, attestation_certificate_key_id: nil)
      verify_arguments(aaguid: aaguid, attestation_certificate_key_id: attestation_certificate_key_id)

      if aaguid
        table_of_contents.entries.detect { |entry| entry.aaguid == aaguid }
      elsif attestation_certificate_key_id
        table_of_contents.entries.detect do |entry|
          entry.attestation_certificate_key_identifiers&.detect do |id|
            id == attestation_certificate_key_id
          end
        end
      end
    end

    def fetch_statement(aaguid: nil, attestation_certificate_key_id: nil)
      verify_arguments(aaguid: aaguid, attestation_certificate_key_id: attestation_certificate_key_id)

      key = "statement_#{aaguid || attestation_certificate_key_id}"
      statement = cache_backend.read(key)
      return statement if statement

      entry = if aaguid
                fetch_entry(aaguid: aaguid)
              elsif attestation_certificate_key_id
                fetch_entry(attestation_certificate_key_id: attestation_certificate_key_id)
              end
      return unless entry

      statement = entry.metadata_statement
      cache_backend.write(key, statement)
      statement
    end

    private

    def verify_arguments(aaguid: nil, attestation_certificate_key_id: nil)
      unless aaguid || attestation_certificate_key_id
        raise ArgumentError, "must pass either aaguid or attestation_certificate_key"
      end

      if aaguid && attestation_certificate_key_id
        raise ArgumentError, "cannot pass both aaguid and attestation_certificate_key"
      end
    end

    def cache_backend
      FidoMetadata.configuration.cache_backend || raise("no cache_backend configured")
    end

    def client
      @client ||= FidoMetadata::Client.new
    end
  end
end
