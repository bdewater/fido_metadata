# frozen_string_literal: true

require "spec_helper"
require "fido_metadata/coercer/user_verification_details"

RSpec.describe FidoMetadata::Coercer::UserVerificationDetails do
  subject { described_class.coerce(value) }

  context "when the value is an array of array of VerificationMethodDescriptor" do
    let(:value) do
      [
        [FidoMetadata::VerificationMethodDescriptor.new]
      ]
    end

    it "returns the same value" do
      expect(subject).to eq(value)
    end
  end

  context "when the value is nil" do
    let(:value) { nil }

    specify do
      expect(subject).to be_nil
    end
  end

  context "when the value is an array of String" do
    let(:file) { File.read(SUPPORT_PATH.join("mds_user_verification_methods.json")) }
    let(:value) { JSON.parse(file) }

    it "returns an array of array of VerificationMethodDescriptor" do
      expect(subject).to include(
        a_collection_containing_exactly(
          kind_of(FidoMetadata::VerificationMethodDescriptor)
        )
      )
      expect(subject[0][0].ba_desc).to be_a(FidoMetadata::BiometricAccuracyDescriptor)
      expect(subject[1][0].ca_desc).to be_a(FidoMetadata::CodeAccuracyDescriptor)
    end
  end
end
