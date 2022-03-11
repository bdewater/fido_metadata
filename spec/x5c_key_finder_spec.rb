# frozen_string_literal: true

require "spec_helper"
require "fido_metadata/x5c_key_finder"

RSpec.describe FidoMetadata::X5cKeyFinder do
  let(:root_key) { generate_key }
  let(:root_dn) { OpenSSL::X509::Name.parse("/DC=org/DC=fake-ca/CN=Fake CA") }
  let(:root_certificate) do
    cert = generate_cert(root_dn, root_key, 1)
    ef = OpenSSL::X509::ExtensionFactory.new
    cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(ef.create_extension("keyUsage", "cRLSign,keyCertSign", true))
    cert.sign(root_key, "sha256")
    cert
  end

  let(:leaf_key) { generate_key }
  let(:leaf_dn) { OpenSSL::X509::Name.parse("/DC=org/DC=fake/CN=Fake") }
  let(:leaf_serial) { 2 }
  let(:leaf_not_after) { Time.now + 3600 }
  let(:leaf_signing_key) { root_key }
  let(:leaf_certificate) do
    cert = generate_cert(
      leaf_dn,
      leaf_key,
      leaf_serial,
      issuer: root_certificate,
      not_after: leaf_not_after
    )
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.config = OpenSSL::Config.parse(leaf_cdp)
    ef.subject_certificate = cert
    cert.add_extension(ef.create_extension("crlDistributionPoints", "@crlDistPts"))
    cert.sign(leaf_signing_key, "sha256")
    cert
  end
  let(:leaf_cdp) { <<-_CNF_ }
    [crlDistPts]
    URI.1 = http://www.example.com/crl
  _CNF_

  let(:crl) { issue_crl([], issuer: root_certificate, issuer_key: root_key) }

  let(:x5c_header) { [Base64.strict_encode64(leaf_certificate.to_der)] }
  subject(:keyfinder) { described_class.from(x5c_header, [root_certificate], [crl]) }

  it "returns the public key from a certificate that is signed by trusted roots and not revoked" do
    expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
    expect(keyfinder.to_pem).to eq(leaf_certificate.public_key.to_pem)
  end

  context "already parsed certificates" do
    let(:x5c_header) { [leaf_certificate] }

    it "returns the public key from a certificate that is signed by trusted roots and not revoked" do
      expect(keyfinder).to be_a(OpenSSL::PKey::RSA)
      expect(keyfinder.to_pem).to eq(leaf_certificate.public_key.to_pem)
    end
  end

  context "certificate" do
    context "expired" do
      let(:leaf_not_after) { Time.now - 3600 }

      it "raises an error" do
        error = "Certificate verification failed: certificate has expired. Certificate subject: " \
          "/DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end

    context "signature could not be verified with the given trusted roots" do
      let(:leaf_signing_key) { generate_key }

      it "raises an error" do
        error = "Certificate verification failed: certificate signature failure. Certificate subject: " \
          "/DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end

    context "could not be chained to a trusted root certificate" do
      subject(:keyfinder) { described_class.from(x5c_header, [], [crl]) }

      it "raises an error" do
        error = "Certificate verification failed: unable to get local issuer certificate. Certificate subject: " \
          "/DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end

    context "revoked" do
      let(:revocation) { [leaf_serial, Time.now - 60, 1] }
      let(:crl) { issue_crl([revocation], issuer: root_certificate, issuer_key: root_key) }

      it "raises an error" do
        error = "Certificate verification failed: certificate revoked. Certificate subject: /DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end
  end

  context "CRL" do
    context "expired" do
      let(:next_up) { Time.now - 60 }
      let(:crl) { issue_crl([], next_up: next_up, issuer: root_certificate, issuer_key: root_key) }

      it "raises an error" do
        error = "Certificate verification failed: CRL has expired. Certificate subject: /DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end

    context "signature could not be verified with the given trusted roots" do
      let(:crl) { issue_crl([], issuer: root_certificate, issuer_key: generate_key) }

      it "raises an error" do
        error = "Certificate verification failed: CRL signature failure. Certificate subject: /DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end

    context "not given" do
      subject(:keyfinder) { described_class.from(x5c_header, [root_certificate], nil) }

      it "raises an error" do
        error = "Certificate verification failed: unable to get certificate CRL. Certificate subject: " \
          "/DC=org/DC=fake/CN=Fake."
        expect { keyfinder }.to raise_error(JWT::VerificationError, error)
      end
    end
  end

  private

  def generate_key
    OpenSSL::PKey::RSA.new(2048)
  end

  def generate_cert(subject, key, serial, issuer: nil, not_before: nil, not_after: nil)
    cert = OpenSSL::X509::Certificate.new
    issuer ||= cert
    cert.version = 2
    cert.serial = serial
    cert.subject = subject
    cert.issuer = issuer.subject
    cert.public_key = key
    now = Time.now
    cert.not_before = not_before || now - 3600
    cert.not_after = not_after || now + 3600
    cert
  end

  def issue_crl(revocations, issuer:, issuer_key:, last_up: nil, next_up: nil)
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    now = Time.now
    crl.last_update = last_up || now - 3600
    crl.next_update = next_up || now + 3600

    revocations.each do |rserial, time, reason_code|
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = rserial
      revoked.time = time
      enum = OpenSSL::ASN1::Enumerated(reason_code)
      ext = OpenSSL::X509::Extension.new("CRLReason", enum)
      revoked.add_extension(ext)
      crl.add_revoked(revoked)
    end

    crlnum = OpenSSL::ASN1::Integer(1)
    crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))

    crl.sign(issuer_key, "sha256")
    crl
  end
end
