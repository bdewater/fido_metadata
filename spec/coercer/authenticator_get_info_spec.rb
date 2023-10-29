# frozen_string_literal: true

require "spec_helper"
require "fido_metadata/authenticator_get_info"

RSpec.describe FidoMetadata::Coercer::AuthenticatorGetInfo do
  subject { described_class.coerce(value) }

  context "when the value is a AuthenticatorGetInfo" do
    let(:value) { FidoMetadata::AuthenticatorGetInfo.new }

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

  context "when the value is String" do
    let(:file) { File.read(SUPPORT_PATH.join("mds_statement_fido2.json")) }
    let(:value) { JSON.parse(file)["authenticatorGetInfo"] }

    it "returns a AuthenticatorGetInfo" do
      expect(subject).to be_a(FidoMetadata::AuthenticatorGetInfo)
    end
  end
end
