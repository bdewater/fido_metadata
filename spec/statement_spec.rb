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
        attachment_hint: ["internal"],
        key_protection: ["hardware", "tee"],
        matcher_protection: ["tee"],
        tc_display: ["any", "tee"],
        tc_display_content_type: "image/png",
        is_key_restricted: true,
        authentication_algorithms: ["secp256r1_ecdsa_sha256_raw"],
        public_key_alg_and_encodings: ["ecc_x962_raw"],
        attestation_types: ["basic_full"],
        upv: [{ "major" => 1, "minor" => 0 }, { "major" => 1, "minor" => 1 }],
      )
      expect(subject.user_verification_details.first.first).to have_attributes(
        user_verification_method: "fingerprint_internal"
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
        attachment_hint: ["external", "wired", "nfc"],
        key_protection: ["hardware", "secure_element"],
        matcher_protection: ["on_chip"],
        authentication_algorithms: ["secp256r1_ecdsa_sha256_raw"],
        public_key_alg_and_encodings: ["ecc_x962_raw"],
        attestation_types: ["basic_full"],
        upv: [
          { "major" => 1, "minor" => 0 },
          { "major" => 1, "minor" => 1 },
          { "major" => 1, "minor" => 2 },
        ],
      )
      expect(subject.user_verification_details.first.first).to have_attributes(
        user_verification_method: "none"
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
        authenticator_version: 5,
        attachment_hint: ["external", "wired", "wireless", "nfc"],
        key_protection: ["hardware", "secure_element"],
        matcher_protection: ["on_chip"],
        authentication_algorithms: ["secp256r1_ecdsa_sha256_raw", "rsassa_pkcsv15_sha256_raw"],
        public_key_alg_and_encodings: ["cose"],
        attestation_types: ["basic_full"],
        upv: [{ "major" => 1, "minor" => 0 }],
      )
      expect(subject.user_verification_details.first.first).to have_attributes(
        user_verification_method: "none"
      )

      expect(subject.authenticator_get_info).to have_attributes(
        versions: ["U2F_V2", "FIDO_2_0"],
        extensions: ["credProtect", "hmac-secret"],
        aaguid: "0132d110bf4e4208a403ab4f5f12efe5",
        options: {
          "plat" => false,
          "rk" => true,
          "clientPin" => true,
          "up" => true,
          "uv" => true,
          "uvToken" => false,
          "config" => false
        },
        max_msg_size: 1200,
        pin_uv_auth_protocols: [1],
        max_credential_count_in_list: 16,
        max_credential_id_length: 128,
        transports: ["usb", "nfc"],
        algorithms: [{ "type" => "public-key", "alg" => -7 }, { "type" => "public-key", "alg" => -257 }],
      )
    end

    context "#trust_store" do
      it "returns a OpenSSL::X509::Store" do
        expect(subject.trust_store).to be_a(OpenSSL::X509::Store)
      end
    end
  end
end
