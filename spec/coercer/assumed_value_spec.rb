# frozen_string_literal: true

require "spec_helper"
require "fido_metadata/coercer/assumed_value"

RSpec.describe FidoMetadata::Coercer::AssumedValue do
  let(:assumed_value) { "assumed value" }

  subject { described_class.new(assumed_value).coerce(value) }

  context "when the value is missing" do
    let(:value) { nil }

    it "returns the same value" do
      expect(subject).to eq("assumed value")
    end
  end

  context "when the value is present" do
    let(:value) { "present value" }

    it "returns the same value" do
      expect(subject).to eq("present value")
    end
  end
end
