# frozen_string_literal: true

require "spec_helper"
require "fido_metadata/coercer/statement"

RSpec.describe FidoMetadata::Coercer::Statement do
  subject { described_class.coerce(value) }

  context "when the value is a Statement" do
    let(:value) { FidoMetadata::Statement.new }

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
    let(:value) { JSON.parse(file) }

    it "returns a Statement" do
      expect(subject).to be_a(FidoMetadata::Statement)
    end
  end
end
