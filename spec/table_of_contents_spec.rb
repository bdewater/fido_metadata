# frozen_string_literal: true

require "spec_helper"
require "fido_metadata/statement"

RSpec.describe FidoMetadata::TableOfContents do
  let(:file) { File.read(SUPPORT_PATH.join("mds_toc.txt")) }
  let(:current_time) { Time.utc(2019, 12, 28) }

  before(:each) do
    allow(Time).to receive(:now).and_return(current_time)
  end

  subject do
    json, _ = JWT.decode(file, nil, false, algorithms: ["ES256"])
    described_class.from_json(json)
  end

  it "#expires_in calculates in how much seconds it will expire" do
    expect(subject.expires_in).to eq(9172800)
  end
end
