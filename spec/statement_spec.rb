# frozen_string_literal: true

require "spec_helper"
require "fido_metadata/statement"

RSpec.describe FidoMetadata::Statement do
  let(:json) { JSON.parse(file) }

  subject { described_class.from_json(json) }

  context "UAF" do
    let(:file) { File.read(SUPPORT_PATH.join("mds_statement_uaf.json")) }

    it "has the expected attributes" do
      expect(subject).to have_attributes(
        aaid: "1234#5678",
        authenticator_version: 2,
        attachment_hint: ["INTERNAL"],
        key_protection: %w[HARDWARE TEE],
        matcher_protection: "TEE",
        tc_display: %w[ANY TEE],
        tc_display_content_type: "image/png",
        is_key_restricted: true,
        is_second_factor_only: false,
        assertion_scheme: "UAFV1TLV",
        authentication_algorithm: "SECP256R1_ECDSA_SHA256_RAW",
        public_key_alg_and_encoding: "ECC_X962_RAW",
        attestation_types: ["BASIC_FULL"],
        upv: [{ "major" => 1, "minor" => 0 }, { "major" => 1, "minor" => 1 }],
      )
      expect(subject.user_verification_details.first.first).to have_attributes(
        user_verification: "FINGERPRINT"
      )
      expect(subject.user_verification_details.first.first.ba_desc).to have_attributes(
        max_templates: 5,
        self_attested_far: 0.00002,
        block_slowdown: 30,
        max_retries: 5,
      )
    end

    context "#trust_store" do
      it "returns a OpenSSL::X509::Store" do
        expect(subject.trust_store).to be_a(OpenSSL::X509::Store)
      end
    end
  end

  context "U2F" do
    let(:file) { File.read(SUPPORT_PATH.join("mds_statement_u2f.json")) }

    it "has the expected attributes" do
      expect(subject).to have_attributes(
        authenticator_version: 2,
        attachment_hint: ["EXTERNAL"],
        key_protection: %w[HARDWARE SECURE_ELEMENT],
        matcher_protection: "ON_CHIP",
        is_second_factor_only: true,
        assertion_scheme: "U2FV1BIN",
        authentication_algorithm: "SECP256R1_ECDSA_SHA256_RAW",
        public_key_alg_and_encoding: "ECC_X962_RAW",
        attestation_types: ["BASIC_FULL"],
        upv: [{ "major" => 1, "minor" => 0 }],
      )
      expect(subject.user_verification_details.first.first).to have_attributes(
        user_verification: "PRESENCE"
      )
    end

    context "#trust_store" do
      it "returns a OpenSSL::X509::Store" do
        expect(subject.trust_store).to be_a(OpenSSL::X509::Store)
      end
    end
  end

  context "FIDO2" do
    let(:file) { File.read(SUPPORT_PATH.join("mds_statement_fido2.json")) }

    it "has the expected attributes" do
      expect(subject).to have_attributes(
        aaguid: "0132d110-bf4e-4208-a403-ab4f5f12efe5",
        authenticator_version: 2,
        attachment_hint: ["EXTERNAL"],
        key_protection: %w[HARDWARE SECURE_ELEMENT],
        matcher_protection: "ON_CHIP",
        assertion_scheme: "FIDOV2",
        authentication_algorithm: "SECP256R1_ECDSA_SHA256_RAW",
        public_key_alg_and_encoding: "COSE",
        attestation_types: ["BASIC_FULL"],
        upv: [{ "major" => 1, "minor" => 0 }],
      )
      expect(subject.user_verification_details.first.first).to have_attributes(
        user_verification: "PRESENCE"
      )
    end

    context "#trust_store" do
      it "returns a OpenSSL::X509::Store" do
        expect(subject.trust_store).to be_a(OpenSSL::X509::Store)
      end
    end
  end
end
