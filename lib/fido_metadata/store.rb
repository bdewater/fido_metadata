# frozen_string_literal: true

require "fido_metadata/client"
require "fido_metadata/table_of_contents"
require "fido_metadata/statement"

module FidoMetadata
  class Store
    METADATA_ENDPOINT = URI("https://mds2.fidoalliance.org/")
    TOC_CACHE_KEY = "metadata_toc"
    STATEMENT_CACHE_KEY = "statement_%s"

    def table_of_contents
      @table_of_contents ||= begin
        key = TOC_CACHE_KEY
        toc = cache_backend.read(key)
        return toc if toc

        json = client.download_toc(METADATA_ENDPOINT)
        toc = FidoMetadata::TableOfContents.from_json(json)
        cache_backend.write(key, toc, expires_in: toc.expires_in, race_condition_ttl: race_condition_ttl)
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

      key = STATEMENT_CACHE_KEY % (aaguid || attestation_certificate_key_id)
      statement = cache_backend.read(key)
      return statement if statement

      entry = if aaguid
                fetch_entry(aaguid: aaguid)
              elsif attestation_certificate_key_id
                fetch_entry(attestation_certificate_key_id: attestation_certificate_key_id)
              end
      return unless entry

      json = client.download_entry(entry.url, expected_hash: entry.hash)
      statement = FidoMetadata::Statement.from_json(json)
      cache_backend.write(
        key,
        statement,
        expires_in: table_of_contents.expires_in,
        race_condition_ttl: race_condition_ttl
      )
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

    def metadata_token
      FidoMetadata.configuration.metadata_token || raise("no metadata_token configured")
    end

    def race_condition_ttl
      FidoMetadata.configuration.race_condition_ttl
    end

    def client
      @client ||= FidoMetadata::Client.new(metadata_token)
    end
  end
end
