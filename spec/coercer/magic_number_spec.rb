# frozen_string_literal: true

require "spec_helper"
require "fido_metadata/coercer/magic_number"

RSpec.describe FidoMetadata::Coercer::MagicNumber do
  let(:bit_mapping) do
    {
      1 => "foo",
      2 => "bar",
    }.freeze
  end

  context "array: false" do
    subject { described_class.new(bit_mapping, array: false).coerce(value) }

    context "when the value is not an Integer" do
      let(:value) { "foo" }

      it "returns the same value" do
        expect(subject).to eq("foo")
      end
    end

    context "when the value is an Integer not defined in the mapping" do
      let(:value) { 9 }

      it "returns nil" do
        expect(subject).to be_nil
      end
    end

    context "when the value is an Integer defined in the mapping" do
      let(:value) { 1 }

      it "returns the key's value" do
        expect(subject).to eq("foo")
      end
    end
  end

  context "array: true" do
    subject { described_class.new(bit_mapping, array: true).coerce(value) }

    context "when the value is not an Array of Integer" do
      let(:value) { ["foo"] }

      it "returns the same value" do
        expect(subject).to eq(["foo"])
      end
    end

    context "when the value is an Array of Integer not defined in the mapping" do
      let(:value) { [9] }

      it "returns an empty array" do
        expect(subject).to be_empty
      end
    end

    context "when the value is an Array of Integer defined in the mapping" do
      let(:value) { [1, 2] }

      it "returns the keys' values" do
        expect(subject).to match_array(%w[foo bar])
      end
    end
  end
end
