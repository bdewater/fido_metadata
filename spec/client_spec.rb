# frozen_string_literal: true

require "spec_helper"
require "fido_metadata/client"

RSpec.describe FidoMetadata::Client do
  let(:uri) { URI("https://mds.fidoalliance.org/") }
  let(:response) { { status: 200, body: "" } }
  let(:current_time) { Time.utc(2023, 10, 4) }

  before(:each) do
    stub_request(:get, uri).to_return(response)
    allow(Time).to receive(:now).and_return(current_time)
  end

  context "#download_toc" do
    let(:toc) { File.read(SUPPORT_PATH.join("mds_toc.txt")) }
    let(:response) { { status: 200, body: toc } }
    let(:trusted_cert) do
      file = File.read(SUPPORT_PATH.join("MDSROOT.crt"))
      OpenSSL::X509::Certificate.new(file)
    end
    let(:extendval_crl) do
      {
        status: 200,
        body: Base64.strict_decode64(File.read(SUPPORT_PATH.join("GlobalSign_Extended_Validation_CA.crl")))
      }
    end
    let(:root_crl) do
      {
        status: 200,
        body: Base64.strict_decode64(File.read(SUPPORT_PATH.join("GlobalSign_Root_CA.crl")))
      }
    end

    before(:each) do
      stub_request(:get, "http://crl.globalsign.com/gs/gsextendvalsha2g3r3.crl").to_return(extendval_crl)
      stub_request(:get, "http://crl.globalsign.com/root-r3.crl").to_return(root_crl)

      allow(FidoMetadata::X5cKeyFinder).to receive(:build_store).and_wrap_original do |method, *args|
        store = method.call(*args)
        store.time = current_time.to_i
        store
      end
    end

    subject { described_class.new.download_toc(uri, trusted_certs: [trusted_cert]) }

    context "when everything's in place" do
      it "returns a MetadataTOCPayload hash with the required keys" do
        expect(subject).to include("nextUpdate", "entries", "no")
      end

      it "has MetadataTOCPayloadEntry objects" do
        expect(subject["entries"]).not_to be_empty
      end
    end

    context "when the x5c certificates are not trusted" do
      let(:current_time) { Time.utc(2019, 5, 12) }

      let(:trusted_cert) do
        file = File.read(SUPPORT_PATH.join("MDSROOT_2.crt"))
        OpenSSL::X509::Certificate.new(file)
      end
      let(:mdcsa_crl) { { status: 200, body: File.read(SUPPORT_PATH.join("MDSCA-1.crl")) } }
      let(:mdsroot_crl) { { status: 200, body: File.read(SUPPORT_PATH.join("MDSROOT.crl")) } }

      before(:each) do
        stub_request(:get, "https://fidoalliance.co.nz/mds/crl/MDSCA-1.crl").to_return(mdcsa_crl)
        stub_request(:get, "https://fidoalliance.co.nz/mds/crl/MDSROOT.crl").to_return(mdsroot_crl)
        stub_request(
          :get,
          "https://fidoalliance.co.nz/safetynetpki/crl/FIDO%20Fake%20Root%20Certificate%20Authority%202018.crl"
        ).to_return(status: 404)

        allow(FidoMetadata::X5cKeyFinder).to receive(:build_store).and_wrap_original do |method, *args|
          store = method.call(*args)
          store.time = current_time.to_i
          store
        end
      end

      context "because the chain cannot be verified" do
        let(:toc) { File.read(SUPPORT_PATH.join("mds_toc_invalid_chain.txt")) }

        specify do
          error = "Certificate verification failed: unable to get local issuer certificate. Certificate subject: " \
           "/C=US/O=FIDO Alliance/OU=FAKE Metadata TOC Signing FAKE/CN=FAKE Metadata TOC Signer 4 FAKE."
          expect { subject }.to raise_error(described_class::UnverifiedSigningKeyError, error)
        end
      end

      context "because the certificate was revoked" do
        let(:toc) { File.read(SUPPORT_PATH.join("mds_toc_revoked.txt")) }

        specify do
          error = "Certificate verification failed: certificate revoked. Certificate subject: " \
           "/C=US/O=FIDO Alliance/OU=FAKE Metadata TOC Signing FAKE/CN=FAKE Metadata TOC Signer 4 FAKE."
          expect { subject }.to raise_error(described_class::UnverifiedSigningKeyError, error)
        end
      end
    end

    context "when the server responds with HTTP 500" do
      let(:response) { { status: 500, body: "test server error" } }

      specify do
        expect { subject }.to raise_error(Net::HTTPFatalError)
      end
    end

    context "when the server times out" do
      specify do
        stub_request(:get, uri).to_timeout

        expect { subject }.to raise_error(Net::OpenTimeout)
      end
    end

    context "when the server responds with malformed JWT" do
      let(:response) { { status: 200, body: "aaa.bbb" } }

      specify do
        expect { subject }.to raise_error(JWT::DecodeError)
      end
    end

    context "when a CRL cannot be downloaded" do
      let(:extendval_crl) { { status: 404 } }

      specify do
        error = "Certificate verification failed: unable to get certificate CRL. Certificate subject: " \
          "/businessCategory=Private Organization/serialNumber=3454284/jurisdictionC=US/jurisdictionST=California" \
          "/C=US/ST=Oregon/L=Beaverton/street=3855 Sw 153Rd Dr/O=FIDO ALLIANCE, INC./CN=mds.fidoalliance.org."
        expect { subject }.to raise_error(described_class::UnverifiedSigningKeyError, error)
      end
    end

    context "when a CRL is malformed" do
      let(:extendval_crl) { { status: 200, body: "crl" } }

      specify do
        expect { subject }.to raise_error(OpenSSL::X509::CRLError)
      end
    end

    context "when a CRL is expired" do
      let(:current_time) { Time.utc(2049, 1, 1) }

      specify do
        error = "Certificate verification failed: CRL has expired. Certificate subject: " \
          "/businessCategory=Private Organization/serialNumber=3454284/jurisdictionC=US" \
          "/jurisdictionST=California/C=US/ST=Oregon/L=Beaverton/street=3855 Sw 153Rd Dr" \
          "/O=FIDO ALLIANCE, INC./CN=mds.fidoalliance.org."
        expect { subject }.to raise_error(described_class::UnverifiedSigningKeyError, error)
      end
    end

    context "when a CRL url redirects to another url" do
      let(:redirecting_url) do
        { status: 302, headers: { location: "http://crl.globalsign.com/gs/redirected.crl" } }
      end

      before(:each) do
        stub_request(:get, "http://crl.globalsign.com/gs/gsextendvalsha2g3r3.crl").to_return(redirecting_url)
        stub_request(:get, "http://crl.globalsign.com/gs/redirected.crl").to_return(extendval_crl)
      end

      specify do
        expect(subject).to include("nextUpdate", "entries", "no")
      end
    end
  end
end
