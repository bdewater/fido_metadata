# frozen_string_literal: true

require "jwt"
require "net/http"
require "openssl"
require "fido_metadata/refinement/fixed_length_secure_compare"
require "fido_metadata/x5c_key_finder"
require "fido_metadata/version"

module FidoMetadata
  class Client
    class DataIntegrityError < StandardError; end
    class InvalidHashError < DataIntegrityError; end
    class UnverifiedSigningKeyError < DataIntegrityError; end

    using Refinement::FixedLengthSecureCompare

    DEFAULT_HEADERS = {
      "Content-Type" => "application/json",
      "User-Agent" => "fido_metadata/#{FidoMetadata::VERSION} (Ruby)"
    }.freeze
    FIDO_ROOT_CERTIFICATES = [OpenSSL::X509::Certificate.new(
      File.read(File.join(__dir__, "..", "Root.cer"))
    )].freeze

    def download_toc(uri, algorithms: ["RS256"], trusted_certs: FIDO_ROOT_CERTIFICATES)
      response = get(uri)
      payload, _ = JWT.decode(response, nil, true, algorithms: algorithms) do |headers|
        jwt_certificates = headers["x5c"].map do |encoded|
          OpenSSL::X509::Certificate.new(Base64.strict_decode64(encoded))
        end
        crls = download_crls(jwt_certificates)

        begin
          X5cKeyFinder.from(jwt_certificates, trusted_certs, crls)
        rescue JWT::VerificationError => e
          raise(UnverifiedSigningKeyError, e.message)
        end
      end
      payload
    end

    private

    def get(uri)
      get = Net::HTTP::Get.new(uri, DEFAULT_HEADERS)
      response = http(uri).request(get)
      response.value
      response.body
    end

    def http(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.port == 443
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.open_timeout = 5
      http.read_timeout = 5
      http
    end

    def download_crls(certificates)
      uris = extract_crl_distribution_points(certificates)

      crls = uris.compact.uniq.map do |uri|
        begin
          get(uri)
        rescue Net::ProtocolError
          # TODO: figure out why test endpoint specifies a missing and unused CRL in the cert chain, and see if this
          # rescue can be removed. If the CRL is used, OpenSSL error 3 (unable to get certificate CRL) will raise.
          nil
        end
      end
      crls.compact.map { |crl| OpenSSL::X509::CRL.new(crl) }
    end

    def extract_crl_distribution_points(certificates)
      certificates.map do |certificate|
        extension = certificate.extensions.detect { |ext| ext.oid == "crlDistributionPoints" }
        # TODO: replace this with proper parsing of deeply nested ASN1 structures
        match = extension&.value&.match(/URI:(?<uri>\S*)/)
        URI(match[:uri]) if match
      end
    end
  end
end
