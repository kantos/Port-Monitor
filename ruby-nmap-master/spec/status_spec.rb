require 'spec_helper'
require 'nmap/status'

describe Status do
  describe "#to_s" do
    let(:state)  { :up }
    let(:reason) { 'syn-ack' }

    subject { described_class.new(state,reason) }

    it "should return the state" do
      subject.to_s.should == state.to_s
    end
  end
end
